#include "app_controller.h"
#include "daemon_application.h"

#include <QtCore/QSettings>
#include <QtCore/qscopeguard.h>
#include <QtGui/QPalette>
#include <QtWidgets/QApplication>
#include <cmath>
#include <QtCore/QDir>
#include <QtCore/QRegularExpression>
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
        QTest::failOnWarning(QRegularExpression{QStringLiteral(".*")});
        QQmlApplicationEngine engine{};
        engine.setInitialProperties({
            {QStringLiteral("app_controller"), QVariant::fromValue(&controller)},
        });
        engine.rootContext()->setContextProperty(QStringLiteral("app_controller"), &controller);
        engine.loadFromModule("Shared.Gui", "Main");
        QVERIFY2(!engine.rootObjects().isEmpty(), "Embedded Shared.Gui module must provide Main");
        emit controller.peers_changed();
        emit controller.transfer_settings_changed();
        QCoreApplication::processEvents();
    }

    void colors_follow_live_palette_changes()
    {
        const auto original_palette = QApplication::palette();
        const auto restore_palette = qScopeGuard([original_palette]() {
            QApplication::setPalette(original_palette);
        });
        daemon_application service{};
        app_controller controller{nullptr, app_paths{directory_.path()}};
        controller.set_service(&service);
        QTest::failOnWarning(QRegularExpression{QStringLiteral(".*")});
        QQmlApplicationEngine engine{};
        engine.setInitialProperties({
            {QStringLiteral("app_controller"), QVariant::fromValue(&controller)},
        });
        engine.rootContext()->setContextProperty(QStringLiteral("app_controller"), &controller);
        engine.loadFromModule("Shared.Gui", "Main");
        QVERIFY(!engine.rootObjects().isEmpty());
        auto *window = engine.rootObjects().first();
        auto color = [window](const char *name) {
            auto *object = window->findChild<QObject *>(QString::fromLatin1(name));
            return object ? object->property("color").value<QColor>() : QColor{};
        };
        emit service.clipboard_transfer_status({}, {}, QStringLiteral("Laptop"),
            int(status_code::TRANSFER_STATUS_COMPLETED), QStringLiteral("Copied"));

        // Change themes while the same QML window and dialogs remain alive.
        for (bool dark : {false, true, false}) {
            QPalette palette = original_palette;
            palette.setColor(QPalette::Window, dark ? QColor{30, 30, 30} : QColor{250, 250, 250});
            palette.setColor(QPalette::Base, dark ? QColor{20, 20, 20} : QColor{255, 255, 255});
            palette.setColor(QPalette::WindowText, dark ? QColor{240, 240, 240} : QColor{32, 32, 32});
            palette.setColor(QPalette::Text, palette.color(QPalette::WindowText));
            QApplication::setPalette(palette);
            QCoreApplication::processEvents();
            QCOMPARE(color("windowBackgroundStart"), palette.color(QPalette::Window));
            QCOMPARE(color("windowBackgroundEnd"), palette.color(QPalette::Base));
            QCOMPARE(color("statusFooter"), palette.color(QPalette::Window));
            QCOMPARE(color("desktopHeading"), palette.color(QPalette::WindowText));
            for (const char *surface : {"PeersDialogSurface", "EgoGraphDialogSurface",
                     "StitchedTopologyDialogSurface", "LogViewerSurface"}) {
                QCOMPARE(color(surface), palette.color(QPalette::Base));
            }
            const auto luminance = [](const QColor &value) {
                const auto linear = [](double channel) {
                    return channel <= 0.04045 ? channel / 12.92 : std::pow((channel + 0.055) / 1.055, 2.4);
                };
                return 0.2126 * linear(value.redF()) + 0.7152 * linear(value.greenF()) + 0.0722 * linear(value.blueF());
            };
            const auto text = luminance(color("statusMessage"));
            const auto background = luminance(palette.color(QPalette::Window));
            const auto contrast = (std::max(text, background) + 0.05) / (std::min(text, background) + 0.05);
            QVERIFY2(contrast >= 4.5, "Status text must stay readable in either theme");
        }
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
