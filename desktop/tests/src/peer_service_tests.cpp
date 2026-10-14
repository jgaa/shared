#include "peer_service.h"

#include <QtCore/QTemporaryDir>
#include <QtCore/QFile>
#include <QtCore/QTimer>
#include <QtTest/QSignalSpy>
#include <QtNetwork/QSslSocket>
#include <QtTest/QTest>

namespace shared::desktop::daemon {

using status_code = shared::v1::TransferStatusCodeGadget::TransferStatusCode;

class peer_service_tests final : public QObject {
    Q_OBJECT

    static shared::v1::TransferStatus status(const QString &id, status_code code)
    {
        shared::v1::TransferId transfer_id{};
        transfer_id.setUuid(id);
        shared::v1::TransferStatus result{};
        result.setTransferId(transfer_id);
        result.setStatus(code);
        return result;
    }

private slots:
    void file_send_waits_for_receiver_completion()
    {
        QTemporaryDir directory{};
        QVERIFY(directory.isValid());
        core::app_paths paths{directory.path()};
        QVERIFY(paths.ensure_directories());
        peer_service service{{}, paths};
        peer_service::outgoing_file_transfer transfer{};
        transfer.transfer_id = QStringLiteral("transfer");
        transfer.recipient_peer_id = QStringLiteral("recipient");
        transfer.recipient_name = QStringLiteral("Laptop");
        transfer.filename = QStringLiteral("photo.png");
        transfer.worker_started = true;
        service.outgoing_file_transfers_.insert(transfer.transfer_id, transfer);
        QSignalSpy results{&service, &peer_service::file_transfer_status};

        service.finish_outgoing_file_send(transfer.transfer_id, true);
        QVERIFY(service.outgoing_file_transfers_.contains(transfer.transfer_id));
        QVERIFY(service.outgoing_file_transfers_.value(transfer.transfer_id).receiver_response_timer->isActive());
        QCOMPARE(results.size(), 0);

        // A repeated acceptance cannot cancel the completion deadline.
        service.handle_transfer_status(nullptr, status(transfer.transfer_id, status_code::TRANSFER_STATUS_ACCEPTED),
            transfer.recipient_peer_id, {});
        QVERIFY(service.outgoing_file_transfers_.value(transfer.transfer_id).receiver_response_timer->isActive());
        QCOMPARE(results.size(), 0);

        service.handle_transfer_status(nullptr, status(transfer.transfer_id, status_code::TRANSFER_STATUS_COMPLETED),
            transfer.recipient_peer_id, {});
        QCOMPARE(results.size(), 1);
        QCOMPARE(results.first().at(3).toInt(), int(status_code::TRANSFER_STATUS_COMPLETED));
        QVERIFY(!service.outgoing_file_transfers_.contains(transfer.transfer_id));
        // A duplicate/late acknowledgement must not produce a second success.
        service.handle_transfer_status(nullptr, status(transfer.transfer_id, status_code::TRANSFER_STATUS_COMPLETED),
            transfer.recipient_peer_id, {});
        QCOMPARE(results.size(), 1);
    }

    void missing_completion_reports_failure()
    {
        QTemporaryDir directory{};
        QVERIFY(directory.isValid());
        core::app_paths paths{directory.path()};
        QVERIFY(paths.ensure_directories());
        peer_service service{{}, paths};
        peer_service::outgoing_file_transfer transfer{};
        transfer.transfer_id = QStringLiteral("transfer");
        transfer.recipient_peer_id = QStringLiteral("recipient");
        service.outgoing_file_transfers_.insert(transfer.transfer_id, transfer);
        QSignalSpy results{&service, &peer_service::file_transfer_status};
        service.arm_transfer_response_timeout(transfer.transfer_id, true, 1, QStringLiteral("No completion acknowledgement"));
        QTRY_COMPARE(results.size(), 1);
        QCOMPARE(results.first().at(3).toInt(), int(status_code::TRANSFER_STATUS_ERROR));
        QVERIFY(!service.outgoing_file_transfers_.contains(transfer.transfer_id));
    }

    void disconnect_reports_pending_transfer_failures()
    {
        QTemporaryDir directory{};
        QVERIFY(directory.isValid());
        core::app_paths paths{directory.path()};
        QVERIFY(paths.ensure_directories());
        peer_service service{{}, paths};
        auto *socket = new QSslSocket{&service};
        peer_service::session_state session{};
        session.authenticated = true;
        session.remote_peer_id = QStringLiteral("recipient");
        service.sessions_.insert(socket, session);
        peer_service::outgoing_file_transfer file{};
        file.transfer_id = QStringLiteral("file");
        file.recipient_peer_id = session.remote_peer_id;
        service.outgoing_file_transfers_.insert(file.transfer_id, file);
        peer_service::outgoing_clipboard_transfer clipboard{};
        clipboard.transfer_id = QStringLiteral("clipboard");
        clipboard.recipient_peer_id = session.remote_peer_id;
        service.outgoing_clipboard_transfers_.insert(clipboard.transfer_id, clipboard);
        peer_service::incoming_file_transfer incoming{};
        incoming.transfer_id = QStringLiteral("incoming-file");
        incoming.sender_peer_id = session.remote_peer_id;
        incoming.temp_path = directory.filePath(QStringLiteral("partial.part"));
        QFile partial{incoming.temp_path};
        QVERIFY(partial.open(QIODevice::WriteOnly));
        QCOMPARE(partial.write("partial"), 7);
        partial.close();
        service.incoming_file_transfers_.insert(incoming.transfer_id, incoming);
        QSignalSpy files{&service, &peer_service::file_transfer_status};
        QSignalSpy copies{&service, &peer_service::clipboard_transfer_status};

        service.handle_disconnected(socket);
        QCOMPARE(files.size(), 2);
        QCOMPARE(copies.size(), 1);
        QCOMPARE(files.first().at(3).toInt(), int(status_code::TRANSFER_STATUS_ERROR));
        QCOMPARE(copies.first().at(3).toInt(), int(status_code::TRANSFER_STATUS_ERROR));
        QVERIFY(service.incoming_file_transfers_.isEmpty());
        QVERIFY(!QFile::exists(incoming.temp_path));
        QVERIFY(service.outgoing_file_transfers_.isEmpty());
        QVERIFY(service.outgoing_clipboard_transfers_.isEmpty());
    }

    void clipboard_pending_approval_keeps_a_deadline()
    {
        QTemporaryDir directory{};
        QVERIFY(directory.isValid());
        core::app_paths paths{directory.path()};
        QVERIFY(paths.ensure_directories());
        peer_service service{{}, paths};
        peer_service::outgoing_clipboard_transfer transfer{};
        transfer.transfer_id = QStringLiteral("transfer");
        transfer.recipient_peer_id = QStringLiteral("recipient");
        service.outgoing_clipboard_transfers_.insert(transfer.transfer_id, transfer);
        service.handle_transfer_status(nullptr, status(transfer.transfer_id, status_code::TRANSFER_STATUS_PENDING_APPROVAL),
            transfer.recipient_peer_id, {});
        const auto *timer = service.outgoing_clipboard_transfers_.value(transfer.transfer_id).receiver_response_timer;
        QVERIFY(timer != nullptr);
        QVERIFY(timer->isActive());
        QVERIFY(timer->interval() > 3 * 60 * 1000);
    }
};

}

QTEST_GUILESS_MAIN(shared::desktop::daemon::peer_service_tests)
#include "peer_service_tests.moc"
