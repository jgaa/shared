#include "shared/desktop/core/enrollment_client.h"

#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/envelope_io.h"
#include "shared/desktop/core/security_materials.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QLoggingCategory>
#include <QtCore/QUuid>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslSocket>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_enrollment_client_log, "shared.desktop.core.enrollment_client")

namespace {

QString certificate_fingerprint(const QSslCertificate &certificate)
{
    return QString::fromLatin1(certificate.digest(QCryptographicHash::Sha256).toHex()).toLower();
}

enrollment_client::result fail_enrollment(
    const QString &message,
    const QString &detail = {})
{
    if (detail.isEmpty()) {
        qCCritical(shared_enrollment_client_log) << message;
    } else {
        qCCritical(shared_enrollment_client_log) << message << detail;
    }

    return {
        .success = false,
        .error_message = detail.isEmpty()
            ? message
            : QStringLiteral("%1: %2").arg(message, detail),
    };
}

}

enrollment_client::enrollment_client(
    const app_paths &app_paths,
    configuration_repository &configuration_repository,
    security_materials &security_materials)
    : app_paths_{app_paths}
    , configuration_repository_{configuration_repository}
    , security_materials_{security_materials}
{
}

enrollment_client::result enrollment_client::enroll(
    const QString &name,
    const QString &host,
    quint16 port,
    const QString &expected_server_fingerprint)
{
    const auto prepared = security_materials_.prepare_enrollment_request(name);
    if (!prepared.success) {
        return fail_enrollment(
            QStringLiteral("Failed to prepare enrollment request"),
            prepared.error_message);
    }

    return enroll_prepared(name, prepared, host, port, expected_server_fingerprint);
}

enrollment_client::result enrollment_client::enroll_prepared(
    const QString &name,
    const security_materials::prepared_enrollment &prepared,
    const QString &host,
    quint16 port,
    const QString &expected_server_fingerprint)
{
    result result{};
    result.verification_code = prepared.verification_code;
    qCInfo(shared_enrollment_client_log)
        << "Starting enrollment"
        << "name=" << name
        << "host=" << host
        << "port=" << port
        << "fingerprint=" << expected_server_fingerprint
        << "verification_code=" << prepared.verification_code;

    QSslSocket socket{};
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    QObject::connect(&socket, &QSslSocket::connected, [&socket]() {
        qCInfo(shared_enrollment_client_log)
            << "TCP connection established to trusted agent"
            << socket.peerAddress().toString()
            << socket.peerPort();
    });
    QObject::connect(&socket, &QSslSocket::encrypted, [&socket]() {
        qCInfo(shared_enrollment_client_log)
            << "TLS session established with trusted agent"
            << socket.peerAddress().toString()
            << socket.peerPort();
    });
    QObject::connect(&socket, &QSslSocket::errorOccurred, [&socket](QAbstractSocket::SocketError) {
        qCWarning(shared_enrollment_client_log) << "Socket error during enrollment" << socket.errorString();
    });
    QObject::connect(&socket, &QSslSocket::sslErrors, [&socket](const QList<QSslError> &errors) {
        for (const auto &error : errors) {
            qCWarning(shared_enrollment_client_log) << "TLS error during enrollment" << error.errorString();
        }
    });
    qCInfo(shared_enrollment_client_log) << "Connecting to trusted agent" << host << port;
    socket.connectToHostEncrypted(host, port);

    if (!socket.waitForEncrypted(15000)) {
        return fail_enrollment(
            QStringLiteral("Failed to establish TLS connection to trusted agent"),
            socket.errorString());
    }

    const auto normalized_expected_fingerprint =
        security_materials::normalize_enrollment_fingerprint(expected_server_fingerprint);
    if (normalized_expected_fingerprint.isEmpty()) {
        return fail_enrollment(QStringLiteral("Enrollment fingerprint must be 8 lowercase hex characters"));
    }

    const auto actual_fingerprint =
        security_materials::normalize_enrollment_fingerprint(certificate_fingerprint(socket.peerCertificate()).left(8));
    qCInfo(shared_enrollment_client_log)
        << "Trusted-agent enrollment fingerprint"
        << "expected=" << security_materials::format_enrollment_fingerprint(normalized_expected_fingerprint)
        << "actual=" << security_materials::format_enrollment_fingerprint(actual_fingerprint);
    if (actual_fingerprint != normalized_expected_fingerprint) {
        socket.disconnectFromHost();
        return fail_enrollment(
            QStringLiteral("Server fingerprint mismatch"),
            QStringLiteral("expected %1, got %2")
                .arg(security_materials::format_enrollment_fingerprint(normalized_expected_fingerprint))
                .arg(security_materials::format_enrollment_fingerprint(actual_fingerprint)));
    }

    shared::v1::Envelope envelope{};
    envelope.setProtocolVersion(1);
    envelope.setMessageId(QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower());
    envelope.setEnrollmentRequest(prepared.request);
    qCInfo(shared_enrollment_client_log)
        << "Prepared enrollment request"
        << "message_id=" << envelope.messageId()
        << "peer_id=" << prepared.peer_id
        << "verification_code=" << prepared.verification_code
        << "csr_bytes=" << prepared.request.certificateRequest().size()
        << "x25519_bytes=" << prepared.request.x25519PublicKey().size();

    const auto payload = envelope_io::serialize(envelope);
    if (socket.write(payload) != payload.size()) {
        return fail_enrollment(
            QStringLiteral("Failed to queue enrollment request"),
            socket.errorString());
    }
    if (!socket.waitForBytesWritten(5000)) {
        return fail_enrollment(
            QStringLiteral("Enrollment request write timed out"),
            socket.errorString());
    }
    qCInfo(shared_enrollment_client_log) << "Enrollment request sent, waiting for decision";

    QByteArray buffer{};
    QElapsedTimer timer{};
    timer.start();
    while (timer.elapsed() < 300000) {
        if (!socket.waitForReadyRead(1000)) {
            if (socket.state() != QAbstractSocket::ConnectedState) {
                return fail_enrollment(
                    QStringLiteral("Connection closed before enrollment decision"),
                    socket.errorString());
            }
            if ((timer.elapsed() % 10000) < 1000) {
                qCInfo(shared_enrollment_client_log) << "Still waiting for enrollment decision" << timer.elapsed() << "ms";
            }
            continue;
        }

        buffer.append(socket.readAll());
        qCInfo(shared_enrollment_client_log) << "Received enrollment response bytes" << buffer.size();

        shared::v1::Envelope response{};
        QString error_message{};
        if (!envelope_io::try_read_message(buffer, response, error_message)) {
            if (!error_message.isEmpty()) {
                return fail_enrollment(
                    QStringLiteral("Failed to decode enrollment response"),
                    error_message);
            }
            continue;
        }

        if (!response.hasEnrollmentDecision()) {
            return fail_enrollment(QStringLiteral("Received unexpected enrollment response"));
        }

        if (!response.enrollmentDecision().approved()) {
            return fail_enrollment(
                QStringLiteral("Enrollment rejected by trusted agent"),
                response.enrollmentDecision().message());
        }

        qCInfo(shared_enrollment_client_log)
            << "Received approved enrollment decision"
            << "peer_list_version=" << response.enrollmentDecision().peerList().version()
            << "signed_cert_bytes=" << response.enrollmentDecision().signedCertificate().size();

        agent_configuration configuration{};
        configuration.initialized = true;
        configuration.role = agent_role::peer;
        configuration.peer_id = prepared.peer_id;
        configuration.name = name;
        configuration.trusted_agent.host = host;
        configuration.trusted_agent.port = port;
        configuration.trusted_agent.pinned_server_fingerprint = normalized_expected_fingerprint;

        const auto finalize_result = security_materials_.finalize_enrollment(configuration, response.enrollmentDecision());
        if (!finalize_result.success) {
            return fail_enrollment(
                QStringLiteral("Failed to finalize enrollment"),
                finalize_result.error_message);
        }

        configuration_repository_.save(configuration);
        qCInfo(shared_enrollment_client_log) << "Enrollment completed successfully for peer" << configuration.peer_id;
        result.success = true;
        return result;
    }

    return fail_enrollment(QStringLiteral("Timed out waiting for enrollment approval"));
}

}
