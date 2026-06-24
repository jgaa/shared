#include "enrollment_server.h"

#include "shared/desktop/core/envelope_io.h"

#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QTimer>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslKey>

namespace shared::desktop::daemon {

Q_LOGGING_CATEGORY(shared_enrollment_server_log, "shared.desktop.daemon.enrollment_server")

namespace {

shared::v1::Envelope make_decision_envelope(const shared::v1::EnrollmentDecision &decision)
{
    shared::v1::Envelope envelope{};
    envelope.setProtocolVersion(1);
    envelope.setMessageId(QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower());
    envelope.setEnrollmentDecision(decision);
    return envelope;
}

shared::v1::EnrollmentDecision make_error_decision(const QString &message)
{
    shared::v1::EnrollmentDecision decision{};
    decision.setApproved(false);
    decision.setMessage(message);
    return decision;
}

shared::v1::EnrollmentDecision make_logged_error_decision(const QString &message)
{
    qCCritical(shared_enrollment_server_log) << message;
    return make_error_decision(message);
}

void write_decision_and_disconnect(QSslSocket *socket, const shared::v1::EnrollmentDecision &decision)
{
    const auto payload = core::envelope_io::serialize(make_decision_envelope(decision));
    if (socket->write(payload) != payload.size()) {
        qCCritical(shared_enrollment_server_log) << "Failed to queue enrollment decision response" << socket->errorString();
    }
    if (!socket->flush()) {
        qCWarning(shared_enrollment_server_log) << "Failed to flush enrollment decision response" << socket->errorString();
    }
    socket->disconnectFromHost();
}

}

enrollment_server::enrollment_server(
    const core::agent_configuration &configuration,
    const core::app_paths &app_paths,
    QObject *parent)
    : QObject{parent}
    , configuration_{configuration}
    , app_paths_{app_paths}
    , pending_enrollment_repository_{app_paths}
    , security_materials_{app_paths}
{
}

bool enrollment_server::start(QString &error_message)
{
    QFile certificate_file{app_paths_.server_certificate_path()};
    QFile key_file{app_paths_.server_key_path()};
    if (!certificate_file.open(QIODevice::ReadOnly) || !key_file.open(QIODevice::ReadOnly)) {
        error_message = QStringLiteral("Failed to open trusted-agent TLS materials");
        qCCritical(shared_enrollment_server_log) << error_message
            << certificate_file.errorString() << key_file.errorString();
        return false;
    }

    QSslConfiguration ssl_configuration = QSslConfiguration::defaultConfiguration();
    ssl_configuration.setLocalCertificate(QSslCertificate{certificate_file.readAll(), QSsl::Pem});
    ssl_configuration.setPrivateKey(QSslKey(
        key_file.readAll(),
        QSsl::Ec,
        QSsl::Pem,
        QSsl::PrivateKey));
    ssl_configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
    server_.setSslConfiguration(ssl_configuration);

    connect(&server_, &QSslServer::pendingConnectionAvailable, this, &enrollment_server::handle_pending_connection);

    if (!server_.listen(QHostAddress::Any, configuration_.enrollment_port)) {
        error_message = server_.errorString();
        qCCritical(shared_enrollment_server_log) << "Failed to listen for enrollment connections" << error_message;
        return false;
    }

    return true;
}

void enrollment_server::stop()
{
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it.key() != nullptr) {
            it.key()->disconnectFromHost();
        }
    }
    sessions_.clear();
    server_.close();
}

void enrollment_server::handle_pending_connection()
{
    while (server_.hasPendingConnections()) {
        auto *socket = qobject_cast<QSslSocket *>(server_.nextPendingConnection());
        if (socket == nullptr) {
            qCWarning(shared_enrollment_server_log) << "Ignoring non-SSL pending connection";
            continue;
        }

        qCInfo(shared_enrollment_server_log)
            << "Accepted incoming enrollment connection"
            << socket->peerAddress().toString()
            << socket->peerPort();

        sessions_.insert(socket, {});

        connect(socket, &QSslSocket::readyRead, this, [this, socket]() {
            handle_socket_ready_read(socket);
        });
        connect(socket, &QSslSocket::errorOccurred, this, [socket](QAbstractSocket::SocketError) {
            qCWarning(shared_enrollment_server_log)
                << "Enrollment socket error"
                << socket->peerAddress().toString()
                << socket->peerPort()
                << socket->errorString();
        });
        connect(socket, &QSslSocket::sslErrors, this, [socket](const QList<QSslError> &errors) {
            for (const auto &error : errors) {
                qCWarning(shared_enrollment_server_log)
                    << "Enrollment TLS error"
                    << socket->peerAddress().toString()
                    << socket->peerPort()
                    << error.errorString();
            }
        });
        connect(socket, &QSslSocket::disconnected, this, [this, socket]() {
            close_socket(socket);
        });
    }
}

void enrollment_server::handle_socket_ready_read(QSslSocket *socket)
{
    auto session = sessions_.find(socket);
    if (session == sessions_.end()) {
        return;
    }

    session->buffer.append(socket->readAll());
    qCInfo(shared_enrollment_server_log)
        << "Received enrollment bytes"
        << socket->peerAddress().toString()
        << socket->peerPort()
        << session->buffer.size();

    shared::v1::Envelope envelope{};
    QString error_message{};
    if (!core::envelope_io::try_read_message(session->buffer, envelope, error_message)) {
        if (!error_message.isEmpty()) {
            qCWarning(shared_enrollment_server_log) << "Invalid enrollment envelope:" << error_message;
            write_decision_and_disconnect(socket, make_error_decision(QStringLiteral("Invalid enrollment envelope")));
        }
        return;
    }

    if (!envelope.hasEnrollmentRequest()) {
        qCWarning(shared_enrollment_server_log) << "Unexpected envelope body during enrollment";
        write_decision_and_disconnect(socket, make_error_decision(QStringLiteral("Unexpected message type during enrollment")));
        return;
    }

    try {
        const auto &request_message = envelope.enrollmentRequest();
        if (!request_message.hasRequestedIdentity()
            || request_message.requestedIdentity().peerId().uuid().isEmpty()
            || request_message.requestedIdentity().name().trimmed().isEmpty()
            || request_message.certificateRequest().isEmpty()
            || request_message.x25519PublicKey().size() != 32
            || request_message.verificationCode().size() != 8) {
            const auto message = QStringLiteral("Enrollment request is missing required fields or has invalid sizes");
            qCWarning(shared_enrollment_server_log) << message;
            write_decision_and_disconnect(socket, make_error_decision(message));
            return;
        }

        qCInfo(shared_enrollment_server_log)
            << "Received enrollment request"
            << "peer_id=" << request_message.requestedIdentity().peerId().uuid()
            << "name=" << request_message.requestedIdentity().name()
            << "verification_code=" << request_message.verificationCode()
            << "csr_bytes=" << request_message.certificateRequest().size()
            << "x25519_bytes=" << request_message.x25519PublicKey().size();

        core::pending_enrollment_request request{};
        request.request_id = QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower();
        request.peer_id = request_message.requestedIdentity().peerId().uuid();
        request.name = request_message.requestedIdentity().name();
        request.verification_code = request_message.verificationCode();
        request.certificate_request = request_message.certificateRequest();
        request.x25519_public_key = request_message.x25519PublicKey();
        request.created_time_ms = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();

        pending_enrollment_repository_.save_request(request);
        session->request_id = request.request_id;
        qCInfo(shared_enrollment_server_log) << "Saved pending enrollment request" << request.request_id;

        auto *poll_timer = new QTimer{socket};
        poll_timer->setInterval(500);
        connect(poll_timer, &QTimer::timeout, this, [this, socket]() {
            maybe_finish_request(socket);
        });
        poll_timer->start();
    } catch (const std::exception &exception) {
        qCCritical(shared_enrollment_server_log) << "Failed to persist enrollment request:" << exception.what();
        write_decision_and_disconnect(
            socket,
            make_error_decision(QStringLiteral("Failed to persist enrollment request: %1").arg(QString::fromUtf8(exception.what()))));
    }
}

void enrollment_server::maybe_finish_request(QSslSocket *socket)
{
    const auto session = sessions_.find(socket);
    if (session == sessions_.end() || session->request_id.isEmpty()) {
        return;
    }

    const auto decision = pending_enrollment_repository_.load_decision(session->request_id);
    if (!decision.has_value() || !decision->decided) {
        return;
    }

    try {
        shared::v1::EnrollmentDecision response{};
        if (decision->approved) {
            QString error_message{};
            const auto request = pending_enrollment_repository_.load_request(session->request_id);
            if (!request.has_value()) {
                response = make_logged_error_decision(QStringLiteral("Pending request disappeared before approval"));
            } else {
                qCInfo(shared_enrollment_server_log) << "Building approved enrollment decision" << session->request_id;
                response = security_materials_.build_approved_decision(configuration_, *request, error_message);
                if (!error_message.isEmpty()) {
                    qCCritical(shared_enrollment_server_log) << "Failed to build approved decision" << error_message;
                    response = make_error_decision(error_message);
                }
            }
        } else {
            qCInfo(shared_enrollment_server_log) << "Enrollment rejected by trusted agent" << decision->message;
            response = make_error_decision(decision->message);
        }

        qCInfo(shared_enrollment_server_log)
            << "Sending enrollment decision"
            << "approved=" << response.approved()
            << "message=" << response.message();
        write_decision_and_disconnect(socket, response);
        pending_enrollment_repository_.remove_request(session->request_id);
        qCInfo(shared_enrollment_server_log) << "Removed pending enrollment request" << session->request_id;
    } catch (const std::exception &exception) {
        qCCritical(shared_enrollment_server_log) << "Enrollment completion failed:" << exception.what();
        write_decision_and_disconnect(
            socket,
            make_error_decision(QStringLiteral("Enrollment processing failed: %1").arg(QString::fromUtf8(exception.what()))));
    }
}

void enrollment_server::close_socket(QSslSocket *socket)
{
    qCInfo(shared_enrollment_server_log)
        << "Closing enrollment socket"
        << socket->peerAddress().toString()
        << socket->peerPort();
    sessions_.remove(socket);
    socket->deleteLater();
}

}
