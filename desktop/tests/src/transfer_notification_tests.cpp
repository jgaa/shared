#include "app_controller.h"
#include "daemon_application.h"

#include <QtCore/QSettings>
#include <QtCore/QDir>
#include <QtCore/QTemporaryDir>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtTest/QSignalSpy>
#include <QtTest/QTest>

using shared::desktop::gui::app_controller;
using shared::desktop::daemon::daemon_application;
using shared::desktop::core::app_paths;
using status_code = shared::v1::TransferStatusCodeGadget::TransferStatusCode;

class transfer_notification_tests final : public QObject {
    Q_OBJECT

    QTemporaryDir directory_{};

private slots:
    void initTestCase()
    {
        QVERIFY(directory_.isValid());
        const auto vault_data = directory_.filePath(QStringLiteral("vault-data"));
        const auto fake_vault = directory_.filePath(QStringLiteral("fake-vault"));
        QVERIFY(QDir{}.mkpath(vault_data));
        QVERIFY(QDir{}.mkpath(fake_vault));
        qputenv("SAFEKEEPING_DATA_DIR", vault_data.toUtf8());
        qputenv("SAFEKEEPING_TEST_FAKE_VAULT_DIR", fake_vault.toUtf8());
        QCoreApplication::setOrganizationName(QStringLiteral("SharedTests"));
        QCoreApplication::setApplicationName(QStringLiteral("NotificationTests"));
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, directory_.path());
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, directory_.path());
    }

    void main_qml_loads_from_embedded_module()
    {
        app_controller controller{nullptr, app_paths{directory_.path()}};
        QQmlApplicationEngine engine{};
        engine.setInitialProperties({
            {QStringLiteral("app_controller"), QVariant::fromValue(&controller)},
        });
        engine.rootContext()->setContextProperty(QStringLiteral("app_controller"), &controller);
        engine.loadFromModule("Shared.Gui", "Main");
        QVERIFY2(!engine.rootObjects().isEmpty(), "Embedded Shared.Gui module must provide Main");
    }

    void terminal_status_notifications_data()
    {
        QTest::addColumn<bool>("file");
        QTest::addColumn<int>("status");
        QTest::addColumn<bool>("success");
        for (bool file : {false, true}) {
            for (auto code : {status_code::TRANSFER_STATUS_COMPLETED, status_code::TRANSFER_STATUS_ERROR,
                     status_code::TRANSFER_STATUS_REJECTED, status_code::TRANSFER_STATUS_CANCELLED}) {
                const auto name = QByteArray(file ? "file-" : "clipboard-") + QByteArray::number(int(code));
                QTest::newRow(name.constData()) << file << int(code) << (code == status_code::TRANSFER_STATUS_COMPLETED);
            }
        }
    }

    void terminal_status_notifications()
    {
        QFETCH(bool, file);
        QFETCH(int, status);
        QFETCH(bool, success);
        daemon_application service{};
        app_controller controller{nullptr, app_paths{directory_.path()}};
        controller.set_service(&service);
        QSignalSpy notifications{&controller, &app_controller::transfer_notification_requested};
        // An empty peer-supplied message must still produce a notification.
        if (file) {
            emit service.file_transfer_status(QStringLiteral("id"), QStringLiteral("peer"), QStringLiteral("Laptop"), status, {});
        } else {
            emit service.clipboard_transfer_status(QStringLiteral("id"), QStringLiteral("peer"), QStringLiteral("Laptop"), status, {});
        }
        QCOMPARE(notifications.size(), 1);
        QCOMPARE(notifications.first().at(2).toBool(), success);
        QVERIFY(notifications.first().at(1).toString().contains(QStringLiteral("Laptop")));
        QVERIFY(!notifications.first().at(0).toString().isEmpty());
    }

    void accepted_and_pending_are_not_success()
    {
        daemon_application service{};
        app_controller controller{nullptr, app_paths{directory_.path()}};
        controller.set_service(&service);
        QSignalSpy notifications{&controller, &app_controller::transfer_notification_requested};
        for (auto code : {status_code::TRANSFER_STATUS_ACCEPTED, status_code::TRANSFER_STATUS_PENDING_APPROVAL}) {
            emit service.file_transfer_status({}, {}, {}, int(code), QStringLiteral("Still in progress"));
            emit service.clipboard_transfer_status({}, {}, {}, int(code), QStringLiteral("Still in progress"));
        }
        QCOMPARE(notifications.size(), 0);
    }

    void immediate_send_failures_notify()
    {
        app_controller controller{nullptr, app_paths{directory_.path()}};
        QSignalSpy notifications{&controller, &app_controller::transfer_notification_requested};
        QVERIFY(!controller.send_clipboard_to_all());
        QVERIFY(!controller.send_files_to_all({QStringLiteral("missing-file")}));
        QCOMPARE(notifications.size(), 2);
        for (const auto &notification : notifications) {
            QVERIFY(!notification.at(2).toBool());
            QVERIFY(!notification.at(1).toString().isEmpty());
        }
    }

    void local_clipboard_copy_notifies()
    {
        app_controller controller{nullptr, app_paths{directory_.path()}};
        QSignalSpy notifications{&controller, &app_controller::transfer_notification_requested};
        controller.copy_to_clipboard(QStringLiteral("Private clipboard contents"));
        QCOMPARE(QGuiApplication::clipboard()->text(), QStringLiteral("Private clipboard contents"));
        QCOMPARE(notifications.size(), 1);
        QVERIFY(notifications.first().at(2).toBool());
        QVERIFY(!notifications.first().at(1).toString().contains(QStringLiteral("Private")));
    }

    void received_transfers_notify()
    {
        daemon_application service{};
        app_controller controller{nullptr, app_paths{directory_.path()}};
        controller.set_service(&service);
        QSignalSpy notifications{&controller, &app_controller::transfer_notification_requested};
        emit service.clipboard_text_received({}, QStringLiteral("Laptop"), QStringLiteral("Received text"));
        QCOMPARE(QGuiApplication::clipboard()->text(), QStringLiteral("Received text"));
        emit service.file_received({}, QStringLiteral("Laptop"), QStringLiteral("photo.png"), {}, 123);
        QCOMPARE(notifications.size(), 2);
        QVERIFY(notifications.at(0).at(2).toBool());
        QVERIFY(notifications.at(1).at(2).toBool());
        QVERIFY(notifications.at(1).at(1).toString().contains(QStringLiteral("photo.png")));
    }
};

QTEST_MAIN(transfer_notification_tests)
#include "transfer_notification_tests.moc"
