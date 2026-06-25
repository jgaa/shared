#include "shared/desktop/core/security_materials.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/envelope_io.h"
#include "shared/desktop/core/openssl_runner.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QSaveFile>
#include <QtCore/QSet>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUuid>
#include <QtNetwork/QSslCertificate>
#include <QtProtobuf/QProtobufSerializer>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <exception>
#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_security_materials_log, "shared.desktop.core.security_materials")

namespace {

QString openssl_subject(const QString &common_name)
{
    auto sanitized = common_name;
    sanitized.replace(QLatin1Char('/'), QLatin1Char('-'));
    if (sanitized.isEmpty()) {
        sanitized = QStringLiteral("shared");
    }

    return QStringLiteral("/CN=%1").arg(sanitized);
}

QSslCertificate load_certificate_from_path(const QString &path)
{
    QFile file{path};
    if (!file.open(QIODevice::ReadOnly)) {
        qCWarning(shared_security_materials_log) << "Failed to open certificate" << path << file.errorString();
        return QSslCertificate{};
    }
    return QSslCertificate{file.readAll(), QSsl::Pem};
}

qint64 to_epoch_ms(const QDateTime &time)
{
    return time.toUTC().toMSecsSinceEpoch();
}

QByteArray peer_list_payload_bytes(const shared::v1::PeerList &peer_list)
{
    shared::v1::PeerListToSign payload{};
    payload.setVersion(peer_list.version());
    payload.setCreatedTimeMs(peer_list.createdTimeMs());
    payload.setTrustedAgentPeerId(peer_list.trustedAgentPeerId());
    payload.setPeers(peer_list.peers());

    QProtobufSerializer serializer{};
    return payload.serialize(&serializer);
}

QByteArray serialize_peer_list(const shared::v1::PeerList &peer_list)
{
    QProtobufSerializer serializer{};
    return peer_list.serialize(&serializer);
}

QString format_short_hex_groups(const QString &value)
{
    if (value.size() != 8) {
        return value;
    }

    return value.first(4) + QLatin1Char('-') + value.sliced(4, 4);
}

QString normalized_peer_name(const QString &value)
{
    return value.trimmed().toCaseFolded();
}

bool validate_peer_entries(const QList<shared::v1::PeerListEntry> &entries, QString &error_message)
{
    QSet<QString> peer_ids{};
    QSet<QString> peer_names{};
    for (const auto &entry : entries) {
        const auto peer_id = entry.identity().peerId().uuid().trimmed();
        if (peer_id.isEmpty()) {
            error_message = QStringLiteral("Peer list contains an entry without a peer id");
            return false;
        }

        if (peer_ids.contains(peer_id)) {
            error_message = QStringLiteral("Peer list contains duplicate peer ids");
            return false;
        }
        peer_ids.insert(peer_id);

        const auto peer_name = normalized_peer_name(entry.identity().name());
        if (peer_name.isEmpty()) {
            error_message = QStringLiteral("Peer list contains an entry without a name");
            return false;
        }

        if (peer_names.contains(peer_name)) {
            error_message = QStringLiteral("Peer list contains duplicate peer names");
            return false;
        }
        peer_names.insert(peer_name);
    }

    return true;
}

[[noreturn]] void throw_security_error(const QString &message)
{
    qCCritical(shared_security_materials_log) << message;
    throw std::runtime_error(message.toStdString());
}

void ensure_file_open(QFileDevice &file, QIODeviceBase::OpenMode mode, const QString &message)
{
    if (!file.open(mode)) {
        throw_security_error(message + QStringLiteral(": ") + file.errorString());
    }
}

void ensure_save_file_open(QSaveFile &file, QIODeviceBase::OpenMode mode, const QString &message)
{
    if (!file.open(mode)) {
        throw_security_error(message + QStringLiteral(": ") + file.errorString());
    }
}

void ensure_write(QFileDevice &file, const QByteArray &data, const QString &message)
{
    if (file.write(data) != data.size()) {
        throw_security_error(message + QStringLiteral(": ") + file.errorString());
    }
}

void ensure_commit(QSaveFile &file, const QString &message)
{
    if (!file.commit()) {
        throw_security_error(message + QStringLiteral(": ") + file.errorString());
    }
}

void remove_if_exists(const QString &path, const QString &message)
{
    if (!QFile::remove(path) && QFile::exists(path)) {
        throw_security_error(message);
    }
}

QByteArray read_file_bytes(const QString &path, const QString &message)
{
    QFile file{path};
    if (!file.open(QIODevice::ReadOnly)) {
        throw_security_error(message + QStringLiteral(": ") + file.errorString());
    }

    return file.readAll();
}

bool verify_peer_list_signature(
    const QByteArray &certificate_der,
    const QByteArray &payload,
    const QByteArray &signature,
    QString &error_message)
{
    const unsigned char *certificate_data =
        reinterpret_cast<const unsigned char *>(certificate_der.constData());
    X509 *certificate = d2i_X509(nullptr, &certificate_data, certificate_der.size());
    if (certificate == nullptr) {
        error_message = QStringLiteral("Failed to parse trusted-agent certificate");
        return false;
    }

    EVP_PKEY *public_key = X509_get_pubkey(certificate);
    X509_free(certificate);
    if (public_key == nullptr) {
        error_message = QStringLiteral("Failed to extract trusted-agent public key");
        return false;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        EVP_PKEY_free(public_key);
        error_message = QStringLiteral("Failed to allocate OpenSSL digest context");
        return false;
    }

    auto verified = false;
    if (EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, public_key) == 1
        && EVP_DigestVerifyUpdate(context, payload.constData(), payload.size()) == 1
        && EVP_DigestVerifyFinal(
            context,
            reinterpret_cast<const unsigned char *>(signature.constData()),
            static_cast<size_t>(signature.size())) == 1) {
        verified = true;
    }

    EVP_MD_CTX_free(context);
    EVP_PKEY_free(public_key);

    if (!verified) {
        error_message = QStringLiteral("Peer-list signature verification failed");
    }

    return verified;
}

}

security_materials::security_materials(const app_paths &app_paths)
    : app_paths_{app_paths}
    , openssl_runner_ptr_{new openssl_runner{}}
{
}

security_materials::trusted_agent_init_result security_materials::initialize_local_trusted_agent(
    const QString &name,
    quint16)
const
{
    trusted_agent_init_result result{};
    result.peer_id = uuid_v7_string();

    try {
        if (!generate_ec_private_key(app_paths_.ca_key_path(), result.error_message)
            || !generate_self_signed_ca(result.error_message)
            || !generate_ec_private_key(app_paths_.server_key_path(), result.error_message)
            || !generate_signed_certificate(
                app_paths_.server_key_path(),
                app_paths_.server_certificate_path(),
                app_paths_.server_certificate_der_path(),
                QStringLiteral("shared-enrollment-server"),
                result.error_message)
            || !generate_ec_private_key(app_paths_.peer_key_path(), result.error_message)
            || !generate_signed_certificate(
                app_paths_.peer_key_path(),
                app_paths_.peer_certificate_path(),
                app_paths_.peer_certificate_der_path(),
                name,
                result.error_message,
                app_paths_.peer_csr_der_path())
            || !generate_x25519_private_key(app_paths_.x25519_private_key_path(), result.error_message)) {
            return result;
        }

        agent_configuration configuration{};
        configuration.initialized = true;
        configuration.role = agent_role::local_trusted_agent;
        configuration.peer_id = result.peer_id;
        configuration.name = name;

        auto peer_list = create_or_update_peer_list(
            configuration,
            nullptr,
            {},
            result.error_message);
        if (!result.error_message.isEmpty()) {
            return result;
        }

        if (!write_peer_list(peer_list, result.error_message)) {
            return result;
        }

        result.enrollment_fingerprint = current_server_enrollment_fingerprint();
        result.success = !result.enrollment_fingerprint.isEmpty();
        if (!result.success && result.error_message.isEmpty()) {
            result.error_message = QStringLiteral("Failed to derive enrollment fingerprint");
        }
    } catch (const std::exception &exception) {
        result.error_message = QString::fromUtf8(exception.what());
    }

    return result;
}

security_materials::prepared_enrollment security_materials::prepare_enrollment_request(const QString &name) const
{
    prepared_enrollment result{};
    result.peer_id = uuid_v7_string();

    if (!generate_ec_private_key(app_paths_.peer_key_path(), result.error_message)) {
        return result;
    }

    remove_if_exists(app_paths_.peer_certificate_path(), QStringLiteral("Failed to remove stale peer certificate file"));
    remove_if_exists(app_paths_.peer_certificate_der_path(), QStringLiteral("Failed to remove stale peer certificate DER file"));
    remove_if_exists(app_paths_.peer_csr_der_path(), QStringLiteral("Failed to remove stale peer CSR file"));

    const auto csr_result = openssl_runner_ptr_->run({
        QStringLiteral("req"),
        QStringLiteral("-new"),
        QStringLiteral("-key"), app_paths_.peer_key_path(),
        QStringLiteral("-subj"), openssl_subject(name),
        QStringLiteral("-outform"), QStringLiteral("DER"),
        QStringLiteral("-out"), app_paths_.peer_csr_der_path(),
    });
    if (!csr_result.success) {
        result.error_message = csr_result.error_message;
        qCCritical(shared_security_materials_log) << "Failed to generate enrollment CSR" << result.error_message;
        return result;
    }

    if (!generate_x25519_private_key(app_paths_.x25519_private_key_path(), result.error_message)) {
        qCCritical(shared_security_materials_log) << "Failed to generate X25519 keypair for enrollment" << result.error_message;
        return result;
    }

    QFile csr_file{app_paths_.peer_csr_der_path()};
    try {
        ensure_file_open(csr_file, QIODevice::ReadOnly, QStringLiteral("Failed to open generated CSR"));
        const auto csr_der = csr_file.readAll();
        const auto x25519_public_key = raw_x25519_public_key(app_paths_.x25519_private_key_path(), result.error_message);
        if (x25519_public_key.isEmpty()) {
            qCCritical(shared_security_materials_log) << "Failed to extract X25519 public key for enrollment" << result.error_message;
            return result;
        }

        result.verification_code = verification_code_for_csr(csr_der);

        shared::v1::PeerId peer_id{};
        peer_id.setUuid(result.peer_id);

        shared::v1::PeerIdentity identity{};
        identity.setPeerId(peer_id);
        identity.setName(name);
        identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

        shared::v1::EnrollmentRequest request{};
        request.setRequestedIdentity(identity);
        request.setCertificateRequest(csr_der);
        request.setVerificationCode(result.verification_code);
        request.setX25519PublicKey(x25519_public_key);

        result.request = request;
        result.success = true;
    } catch (const std::exception &exception) {
        result.error_message = QString::fromUtf8(exception.what());
        qCCritical(shared_security_materials_log) << "Failed to prepare enrollment request" << result.error_message;
    }
    return result;
}

security_materials::operation_result security_materials::finalize_enrollment(
    const agent_configuration &,
    const shared::v1::EnrollmentDecision &decision) const
{
    operation_result result{};
    try {
        if (!decision.approved()) {
            result.error_message = decision.message();
            qCCritical(shared_security_materials_log) << "Enrollment decision was rejected" << result.error_message;
            return result;
        }

        if (!decision.hasSignedCertificate() || !decision.hasPeerList()) {
            result.error_message = QStringLiteral("Enrollment decision is missing required data");
            qCCritical(shared_security_materials_log) << result.error_message;
            return result;
        }

        {
            QSaveFile certificate_file{app_paths_.peer_certificate_der_path()};
            ensure_save_file_open(certificate_file, QIODevice::WriteOnly | QIODevice::Truncate, QStringLiteral("Failed to open peer certificate file"));
            ensure_write(certificate_file, decision.signedCertificate(), QStringLiteral("Failed to write peer certificate file"));
            ensure_commit(certificate_file, QStringLiteral("Failed to commit peer certificate file"));
        }

        const auto pem_result = openssl_runner_ptr_->run({
            QStringLiteral("x509"),
            QStringLiteral("-inform"), QStringLiteral("DER"),
            QStringLiteral("-in"), app_paths_.peer_certificate_der_path(),
            QStringLiteral("-out"), app_paths_.peer_certificate_path(),
        });
        if (!pem_result.success) {
            result.error_message = pem_result.error_message;
            qCCritical(shared_security_materials_log) << "Failed to convert peer certificate to PEM" << result.error_message;
            return result;
        }

        QString installed_fingerprint_error{};
        const auto installed_fingerprint =
            certificate_fingerprint(app_paths_.peer_certificate_path(), installed_fingerprint_error);
        if (installed_fingerprint.isEmpty()) {
            result.error_message = installed_fingerprint_error.isEmpty()
                ? QStringLiteral("Failed to derive installed peer certificate fingerprint")
                : installed_fingerprint_error;
            qCCritical(shared_security_materials_log)
                << "Failed to inspect installed peer certificate"
                << result.error_message;
            return result;
        }

        qCInfo(shared_security_materials_log)
            << "Installed enrolled peer certificate"
            << "fingerprint=" << installed_fingerprint
            << "certificate_path=" << app_paths_.peer_certificate_path();

        if (decision.hasTrustedAgentCaCertificate()) {
            QSaveFile ca_file{app_paths_.pinned_trusted_agent_ca_certificate_path()};
            ensure_save_file_open(ca_file, QIODevice::WriteOnly | QIODevice::Truncate, QStringLiteral("Failed to open pinned trusted-agent CA file"));
            ensure_write(ca_file, decision.trustedAgentCaCertificate(), QStringLiteral("Failed to write pinned trusted-agent CA file"));
            ensure_commit(ca_file, QStringLiteral("Failed to commit pinned trusted-agent CA file"));
        }

        if (!validate_peer_list(decision.peerList(), result.error_message)) {
            qCCritical(shared_security_materials_log) << "Failed to validate peer list from enrollment decision" << result.error_message;
            return result;
        }

        {
            QProtobufSerializer serializer{};
            const auto peer_list_bytes = decision.peerList().serialize(&serializer);
            QSaveFile peer_list_file{app_paths_.peer_list_path()};
            ensure_save_file_open(peer_list_file, QIODevice::WriteOnly | QIODevice::Truncate, QStringLiteral("Failed to open peer-list file"));
            ensure_write(peer_list_file, peer_list_bytes, QStringLiteral("Failed to write peer-list file"));
            ensure_commit(peer_list_file, QStringLiteral("Failed to commit peer-list file"));
        }

        result.success = true;
    } catch (const std::exception &exception) {
        result.error_message = QString::fromUtf8(exception.what());
        qCCritical(shared_security_materials_log) << "Failed to finalize enrollment" << result.error_message;
    }
    return result;
}

security_materials::operation_result security_materials::write_rejection_marker(const QString &message) const
{
    return {
        .success = false,
        .error_message = message,
    };
}

shared::v1::EnrollmentDecision security_materials::build_approved_decision(
    const agent_configuration &configuration,
    const pending_enrollment_request &request,
    QString &error_message) const
{
    shared::v1::EnrollmentDecision decision{};

    QTemporaryDir temporary_dir{};
    if (!temporary_dir.isValid()) {
        error_message = QStringLiteral("Failed to create temporary directory for certificate signing");
        return decision;
    }

    const auto csr_path = temporary_dir.filePath(QStringLiteral("request.csr.der"));
    const auto certificate_der_path = temporary_dir.filePath(QStringLiteral("peer-cert.der"));
    const auto certificate_pem_path = temporary_dir.filePath(QStringLiteral("peer-cert.pem"));

    {
        QFile csr_file{csr_path};
        ensure_file_open(csr_file, QIODevice::WriteOnly | QIODevice::Truncate, QStringLiteral("Failed to open temporary CSR file"));
        ensure_write(csr_file, request.certificate_request, QStringLiteral("Failed to write temporary CSR file"));
    }

    const auto sign_result = openssl_runner_ptr_->run({
        QStringLiteral("x509"),
        QStringLiteral("-req"),
        QStringLiteral("-inform"), QStringLiteral("DER"),
        QStringLiteral("-in"), csr_path,
        QStringLiteral("-CA"), app_paths_.ca_certificate_path(),
        QStringLiteral("-CAkey"), app_paths_.ca_key_path(),
        QStringLiteral("-CAserial"), app_paths_.ca_serial_path(),
        QStringLiteral("-out"), certificate_pem_path,
        QStringLiteral("-days"), QStringLiteral("36500"),
        QStringLiteral("-sha256"),
    });
    if (!sign_result.success) {
        error_message = sign_result.error_message;
        return decision;
    }

    const auto der_result = openssl_runner_ptr_->run({
        QStringLiteral("x509"),
        QStringLiteral("-in"), certificate_pem_path,
        QStringLiteral("-outform"), QStringLiteral("DER"),
        QStringLiteral("-out"), certificate_der_path,
    });
    if (!der_result.success) {
        error_message = der_result.error_message;
        return decision;
    }

    QString issued_fingerprint_error{};
    const auto issued_fingerprint = certificate_fingerprint(certificate_pem_path, issued_fingerprint_error);
    if (issued_fingerprint.isEmpty()) {
        error_message = issued_fingerprint_error.isEmpty()
            ? QStringLiteral("Failed to derive issued enrollment certificate fingerprint")
            : issued_fingerprint_error;
        return decision;
    }

    qCInfo(shared_security_materials_log)
        << "Issued enrollment certificate"
        << "peer_id=" << request.peer_id
        << "fingerprint=" << issued_fingerprint
        << "certificate_path=" << certificate_pem_path;

    auto peer_list = create_or_update_peer_list(
        configuration,
        &request,
        certificate_pem_path,
        error_message);
    if (!error_message.isEmpty()) {
        return decision;
    }

    if (!write_peer_list(peer_list, error_message)) {
        return decision;
    }

    QFile certificate_file{certificate_der_path};
    ensure_file_open(certificate_file, QIODevice::ReadOnly, QStringLiteral("Failed to open signed certificate file"));

    decision.setApproved(true);
    decision.setMessage(QStringLiteral("Enrollment approved"));
    decision.setSignedCertificate(certificate_file.readAll());
    decision.setPeerList(peer_list);
    decision.setTrustedAgentCaCertificate(current_ca_certificate_der());
    return decision;
}

QString security_materials::current_server_enrollment_fingerprint() const
{
    QString error_message{};
    return format_enrollment_fingerprint(enrollment_fingerprint(app_paths_.server_certificate_path(), error_message));
}

QByteArray security_materials::current_ca_certificate_der() const
{
    QString error_message{};
    return certificate_der(app_paths_.ca_certificate_path(), error_message);
}

shared::v1::PeerList security_materials::current_peer_list(QString &error_message) const
{
    return load_peer_list(error_message);
}

security_materials::peer_list_update_result security_materials::store_peer_list_if_newer(
    const shared::v1::PeerList &peer_list) const
{
    peer_list_update_result result{};
    if (!validate_peer_list(peer_list, result.error_message)) {
        return result;
    }

    QString current_error{};
    const auto current_peer_list = load_peer_list(current_error);
    if (!current_error.isEmpty() && QFile::exists(app_paths_.peer_list_path())) {
        result.error_message = current_error;
        return result;
    }

    if (current_peer_list.version() > peer_list.version()) {
        result.success = true;
        return result;
    }

    if (current_peer_list.version() == peer_list.version() && current_peer_list.version() != 0) {
        if (serialize_peer_list(current_peer_list) != serialize_peer_list(peer_list)) {
            result.error_message = QStringLiteral("Received conflicting peer list for existing version");
            return result;
        }

        result.success = true;
        return result;
    }

    QString write_error{};
    if (!write_peer_list(peer_list, write_error)) {
        result.error_message = write_error;
        return result;
    }

    result.success = true;
    result.updated = true;
    return result;
}

bool security_materials::validate_peer_list(
    const shared::v1::PeerList &peer_list,
    QString &error_message) const
{
    if (peer_list.version() == 0) {
        error_message = QStringLiteral("Peer list must have a non-zero version");
        return false;
    }

    if (!peer_list.hasTrustedAgentPeerId() || peer_list.trustedAgentPeerId().uuid().isEmpty()) {
        error_message = QStringLiteral("Peer list is missing trusted-agent peer id");
        return false;
    }

    if (peer_list.signature().isEmpty()) {
        error_message = QStringLiteral("Peer list is missing signature");
        return false;
    }

    if (!validate_peer_entries(peer_list.peers(), error_message)) {
        return false;
    }

    QByteArray authority_certificate_der{};
    try {
        if (QFile::exists(app_paths_.ca_certificate_path())) {
            authority_certificate_der = certificate_der(app_paths_.ca_certificate_path(), error_message);
        } else {
            authority_certificate_der = read_file_bytes(
                app_paths_.pinned_trusted_agent_ca_certificate_path(),
                QStringLiteral("Failed to open pinned trusted-agent CA certificate"));
        }
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return false;
    }

    if (authority_certificate_der.isEmpty()) {
        if (error_message.isEmpty()) {
            error_message = QStringLiteral("Trusted-agent CA certificate is unavailable");
        }
        return false;
    }

    return verify_peer_list_signature(
        authority_certificate_der,
        peer_list_payload_bytes(peer_list),
        peer_list.signature(),
        error_message);
}

bool security_materials::is_known_peer_identity(
    const QString &peer_id,
    const QString &peer_name,
    const QString &certificate_fingerprint_sha256,
    QString &error_message) const
{
    const auto peer_list = load_peer_list(error_message);
    if (!error_message.isEmpty()) {
        return false;
    }

    for (const auto &entry : peer_list.peers()) {
        if (entry.identity().peerId().uuid() != peer_id) {
            continue;
        }

        if (normalized_peer_name(entry.identity().name()) != normalized_peer_name(peer_name)) {
            qCWarning(shared_security_materials_log)
                << "Peer name mismatch"
                << "peer_id=" << peer_id
                << "expected=" << entry.identity().name()
                << "actual=" << peer_name;
            error_message = QStringLiteral("Peer name does not match the signed peer list");
            return false;
        }

        if (entry.certificateFingerprintSha256() == certificate_fingerprint_sha256) {
            return true;
        }

        qCWarning(shared_security_materials_log)
            << "Peer certificate fingerprint mismatch"
            << "peer_id=" << peer_id
            << "expected=" << entry.certificateFingerprintSha256()
            << "actual=" << certificate_fingerprint_sha256;
        error_message = QStringLiteral("Peer certificate fingerprint does not match the signed peer list");
        return false;
    }

    error_message = QStringLiteral("Peer is not present in the signed peer list");
    return false;
}

QString security_materials::certificate_fingerprint_sha256(const QSslCertificate &certificate)
{
    if (certificate.isNull()) {
        return {};
    }

    return QString::fromLatin1(QCryptographicHash::hash(certificate.toDer(), QCryptographicHash::Sha256).toHex());
}

QString security_materials::normalize_enrollment_fingerprint(const QString &value)
{
    QString normalized = value.trimmed().toLower();
    normalized.remove(QLatin1Char('-'));
    normalized.remove(QLatin1Char(' '));

    if (normalized.size() != 8) {
        return {};
    }

    for (const auto character : normalized) {
        if (!character.isDigit()
            && (character < QLatin1Char('a') || character > QLatin1Char('f'))) {
            return {};
        }
    }

    return normalized;
}

QString security_materials::format_enrollment_fingerprint(const QString &value)
{
    const auto normalized = normalize_enrollment_fingerprint(value);
    if (normalized.isEmpty()) {
        return value.trimmed().toLower();
    }

    return format_short_hex_groups(normalized);
}

bool security_materials::generate_ec_private_key(const QString &path, QString &error_message) const
{
    const auto result = openssl_runner_ptr_->run({
        QStringLiteral("genpkey"),
        QStringLiteral("-algorithm"), QStringLiteral("EC"),
        QStringLiteral("-pkeyopt"), QStringLiteral("ec_paramgen_curve:P-256"),
        QStringLiteral("-out"), path,
    });

    if (!result.success) {
        error_message = result.error_message;
    }

    return result.success;
}

bool security_materials::generate_x25519_private_key(const QString &path, QString &error_message) const
{
    const auto result = openssl_runner_ptr_->run({
        QStringLiteral("genpkey"),
        QStringLiteral("-algorithm"), QStringLiteral("X25519"),
        QStringLiteral("-out"), path,
    });

    if (!result.success) {
        error_message = result.error_message;
    }

    return result.success;
}

bool security_materials::generate_self_signed_ca(QString &error_message) const
{
    const auto result = openssl_runner_ptr_->run({
        QStringLiteral("req"),
        QStringLiteral("-x509"),
        QStringLiteral("-new"),
        QStringLiteral("-key"), app_paths_.ca_key_path(),
        QStringLiteral("-sha256"),
        QStringLiteral("-days"), QStringLiteral("36500"),
        QStringLiteral("-subj"), QStringLiteral("/CN=shared-trusted-agent-ca"),
        QStringLiteral("-out"), app_paths_.ca_certificate_path(),
    });

    if (!result.success) {
        error_message = result.error_message;
    }

    return result.success;
}

bool security_materials::generate_signed_certificate(
    const QString &key_path,
    const QString &certificate_path,
    const QString &certificate_der_path,
    const QString &subject_common_name,
    QString &error_message,
    const QString &csr_der_path) const
{
    QTemporaryDir temporary_dir{};
    if (csr_der_path.isEmpty() && !temporary_dir.isValid()) {
        error_message = QStringLiteral("Failed to create temporary directory for certificate request");
        qCCritical(shared_security_materials_log) << error_message;
        return false;
    }

    const auto effective_csr_path = csr_der_path.isEmpty()
        ? temporary_dir.filePath(QStringLiteral("request.csr.der"))
        : csr_der_path;

    const auto csr_result = openssl_runner_ptr_->run({
        QStringLiteral("req"),
        QStringLiteral("-new"),
        QStringLiteral("-key"), key_path,
        QStringLiteral("-subj"), openssl_subject(subject_common_name),
        QStringLiteral("-outform"), QStringLiteral("DER"),
        QStringLiteral("-out"), effective_csr_path,
    });
    if (!csr_result.success) {
        error_message = csr_result.error_message;
        return false;
    }

    const auto cert_result = openssl_runner_ptr_->run({
        QStringLiteral("x509"),
        QStringLiteral("-req"),
        QStringLiteral("-inform"), QStringLiteral("DER"),
        QStringLiteral("-in"), effective_csr_path,
        QStringLiteral("-CA"), app_paths_.ca_certificate_path(),
        QStringLiteral("-CAkey"), app_paths_.ca_key_path(),
        QStringLiteral("-CAcreateserial"),
        QStringLiteral("-CAserial"), app_paths_.ca_serial_path(),
        QStringLiteral("-out"), certificate_path,
        QStringLiteral("-days"), QStringLiteral("36500"),
        QStringLiteral("-sha256"),
    });
    if (!cert_result.success) {
        error_message = cert_result.error_message;
        return false;
    }

    const auto der_result = openssl_runner_ptr_->run({
        QStringLiteral("x509"),
        QStringLiteral("-in"), certificate_path,
        QStringLiteral("-outform"), QStringLiteral("DER"),
        QStringLiteral("-out"), certificate_der_path,
    });
    if (!der_result.success) {
        error_message = der_result.error_message;
        return false;
    }

    return true;
}

bool security_materials::write_peer_list(const shared::v1::PeerList &peer_list, QString &error_message) const
{
    QProtobufSerializer serializer{};
    const auto bytes = peer_list.serialize(&serializer);
    QSaveFile file{app_paths_.peer_list_path()};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        error_message = QStringLiteral("Failed to open peer-list file");
        return false;
    }

    if (file.write(bytes) != bytes.size()) {
        error_message = QStringLiteral("Failed to write peer-list file");
        qCCritical(shared_security_materials_log) << error_message << file.errorString();
        return false;
    }
    if (!file.commit()) {
        error_message = QStringLiteral("Failed to commit peer-list file");
        qCCritical(shared_security_materials_log) << error_message << file.errorString();
        return false;
    }

    return true;
}

shared::v1::PeerList security_materials::load_peer_list(QString &error_message) const
{
    shared::v1::PeerList peer_list{};
    QFile file{app_paths_.peer_list_path()};
    if (!file.exists()) {
        return peer_list;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        error_message = QStringLiteral("Failed to open peer-list file");
        return peer_list;
    }

    QProtobufSerializer serializer{};
    if (!peer_list.deserialize(&serializer, file.readAll())) {
        error_message = QStringLiteral("Failed to deserialize peer-list");
    }

    return peer_list;
}

shared::v1::PeerList security_materials::create_or_update_peer_list(
    const agent_configuration &configuration,
    const pending_enrollment_request *request,
    const QString &request_certificate_path,
    QString &error_message) const
{
    auto current_peer_list = load_peer_list(error_message);
    if (!error_message.isEmpty() && QFile::exists(app_paths_.peer_list_path())) {
        return current_peer_list;
    }
    error_message.clear();

    QList<shared::v1::PeerListEntry> peers{};
    if (current_peer_list.version() == 0) {
        peers.append(local_peer_list_entry(configuration, error_message));
        if (!error_message.isEmpty()) {
            return {};
        }
    } else {
        peers = current_peer_list.peers();
    }

    shared::v1::PeerList peer_list{};
    peer_list.setVersion(current_peer_list.version() == 0 ? 1 : current_peer_list.version() + 1);
    peer_list.setCreatedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());

    shared::v1::PeerId trusted_agent_peer_id{};
    trusted_agent_peer_id.setUuid(configuration.peer_id);
    peer_list.setTrustedAgentPeerId(trusted_agent_peer_id);

    if (current_peer_list.version() != 0) {
        peer_list.setPeers(current_peer_list.peers());
    } else {
        peer_list.setPeers(peers);
    }

    if (request != nullptr) {
        if (request_certificate_path.isEmpty()) {
            error_message = QStringLiteral("Issued request certificate path is required");
            return {};
        }

        auto entries = peer_list.peers();
        auto updated = false;
        for (auto &entry : entries) {
            if (entry.identity().peerId().uuid() == request->peer_id) {
                entry = peer_list_entry_for_request(*request, request_certificate_path, error_message);
                updated = true;
                break;
            }
        }
        if (!updated) {
            entries.append(peer_list_entry_for_request(*request, request_certificate_path, error_message));
        }
        if (!error_message.isEmpty()) {
            return {};
        }
        peer_list.setPeers(entries);
    }

    if (!validate_peer_entries(peer_list.peers(), error_message)) {
        return {};
    }

    shared::v1::PeerListToSign peer_list_to_sign{};
    peer_list_to_sign.setVersion(peer_list.version());
    peer_list_to_sign.setCreatedTimeMs(peer_list.createdTimeMs());
    peer_list_to_sign.setTrustedAgentPeerId(peer_list.trustedAgentPeerId());
    peer_list_to_sign.setPeers(peer_list.peers());

    const auto signature = sign_peer_list_payload(peer_list_to_sign, error_message);
    if (signature.isEmpty()) {
        return {};
    }

    peer_list.setSignature(signature);
    peer_list.setSignatureAlgorithm(QStringLiteral("sha256-ecdsa"));
    return peer_list;
}

QByteArray security_materials::sign_peer_list_payload(
    const shared::v1::PeerListToSign &peer_list_to_sign,
    QString &error_message) const
{
    QTemporaryDir temporary_dir{};
    if (!temporary_dir.isValid()) {
        error_message = QStringLiteral("Failed to create temporary signing directory");
        return {};
    }

    QProtobufSerializer serializer{};
    const auto payload = peer_list_to_sign.serialize(&serializer);

    const auto payload_path = temporary_dir.filePath(QStringLiteral("peer-list.bin"));
    const auto signature_path = temporary_dir.filePath(QStringLiteral("peer-list.sig"));

    QFile payload_file{payload_path};
    ensure_file_open(payload_file, QIODevice::WriteOnly | QIODevice::Truncate, QStringLiteral("Failed to open peer-list payload file"));
    ensure_write(payload_file, payload, QStringLiteral("Failed to write peer-list payload file"));
    payload_file.close();

    const auto result = openssl_runner_ptr_->run({
        QStringLiteral("dgst"),
        QStringLiteral("-sha256"),
        QStringLiteral("-sign"), app_paths_.ca_key_path(),
        QStringLiteral("-out"), signature_path,
        payload_path,
    });
    if (!result.success) {
        error_message = result.error_message;
        return {};
    }

    QFile signature_file{signature_path};
    ensure_file_open(signature_file, QIODevice::ReadOnly, QStringLiteral("Failed to open peer-list signature file"));
    return signature_file.readAll();
}

QByteArray security_materials::raw_x25519_public_key(const QString &private_key_path, QString &error_message) const
{
    QFile file{private_key_path};
    if (!file.open(QIODevice::ReadOnly)) {
        error_message = QStringLiteral("Failed to open X25519 private key");
        qCCritical(shared_security_materials_log) << error_message << file.errorString();
        return {};
    }

    const auto pem_data = file.readAll();
    BIO *bio = BIO_new_mem_buf(pem_data.constData(), static_cast<int>(pem_data.size()));
    if (bio == nullptr) {
        error_message = QStringLiteral("Failed to create OpenSSL BIO for X25519 key");
        return {};
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pkey == nullptr) {
        error_message = QStringLiteral("Failed to parse X25519 private key");
        return {};
    }

    size_t key_length = 32;
    QByteArray public_key(static_cast<qsizetype>(key_length), Qt::Uninitialized);
    if (EVP_PKEY_get_raw_public_key(
            pkey,
            reinterpret_cast<unsigned char *>(public_key.data()),
            &key_length) != 1) {
        EVP_PKEY_free(pkey);
        error_message = QStringLiteral("Failed to extract X25519 public key");
        return {};
    }

    EVP_PKEY_free(pkey);
    public_key.resize(static_cast<qsizetype>(key_length));
    return public_key;
}

QString security_materials::certificate_fingerprint(const QString &certificate_path, QString &error_message) const
{
    const auto der = certificate_der(certificate_path, error_message);
    if (der.isEmpty()) {
        return {};
    }

    return QString::fromLatin1(QCryptographicHash::hash(der, QCryptographicHash::Sha256).toHex());
}

QString security_materials::enrollment_fingerprint(const QString &certificate_path, QString &error_message) const
{
    const auto full_fingerprint = certificate_fingerprint(certificate_path, error_message);
    if (full_fingerprint.isEmpty()) {
        return {};
    }

    return full_fingerprint.left(8);
}

QByteArray security_materials::certificate_der(const QString &certificate_path, QString &error_message) const
{
    const auto certificate = load_certificate_from_path(certificate_path);
    if (certificate.isNull()) {
        error_message = QStringLiteral("Failed to load certificate from %1").arg(certificate_path);
        return {};
    }

    return certificate.toDer();
}

qint64 security_materials::certificate_not_before_ms(const QString &certificate_path, QString &error_message) const
{
    const auto certificate = load_certificate_from_path(certificate_path);
    if (certificate.isNull()) {
        error_message = QStringLiteral("Failed to load certificate validity");
        return {};
    }

    return to_epoch_ms(certificate.effectiveDate());
}

qint64 security_materials::certificate_not_after_ms(const QString &certificate_path, QString &error_message) const
{
    const auto certificate = load_certificate_from_path(certificate_path);
    if (certificate.isNull()) {
        error_message = QStringLiteral("Failed to load certificate validity");
        return {};
    }

    return to_epoch_ms(certificate.expiryDate());
}

QString security_materials::verification_code_for_csr(const QByteArray &csr_der) const
{
    return QString::fromLatin1(QCryptographicHash::hash(csr_der, QCryptographicHash::Sha256).toHex().left(8));
}

QString security_materials::uuid_v7_string() const
{
    return QUuid::createUuidV7().toString(QUuid::WithoutBraces).toLower();
}

shared::v1::PeerListEntry security_materials::local_peer_list_entry(
    const agent_configuration &configuration,
    QString &error_message) const
{
    shared::v1::PeerListEntry entry{};
    shared::v1::PeerIdentity identity{};
    shared::v1::PeerId peer_id{};
    peer_id.setUuid(configuration.peer_id);
    identity.setPeerId(peer_id);
    identity.setName(configuration.name);
    identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

    entry.setIdentity(identity);
    entry.setCertificateFingerprintSha256(certificate_fingerprint(app_paths_.peer_certificate_path(), error_message));
    entry.setCertificateNotBeforeMs(certificate_not_before_ms(app_paths_.peer_certificate_path(), error_message));
    entry.setCertificateNotAfterMs(certificate_not_after_ms(app_paths_.peer_certificate_path(), error_message));
    entry.setX25519PublicKey(raw_x25519_public_key(app_paths_.x25519_private_key_path(), error_message));

    return entry;
}

shared::v1::PeerListEntry security_materials::peer_list_entry_for_request(
    const pending_enrollment_request &request,
    const QString &certificate_path,
    QString &error_message) const
{
    shared::v1::PeerListEntry entry{};
    shared::v1::PeerIdentity identity{};
    shared::v1::PeerId peer_id{};
    peer_id.setUuid(request.peer_id);
    identity.setPeerId(peer_id);
    identity.setName(request.name);
    identity.setPlatform(shared::v1::PlatformGadget::Platform::PLATFORM_LINUX);

    entry.setIdentity(identity);
    entry.setCertificateFingerprintSha256(certificate_fingerprint(certificate_path, error_message));
    entry.setCertificateNotBeforeMs(certificate_not_before_ms(certificate_path, error_message));
    entry.setCertificateNotAfterMs(certificate_not_after_ms(certificate_path, error_message));
    entry.setX25519PublicKey(request.x25519_public_key);

    return entry;
}

}
