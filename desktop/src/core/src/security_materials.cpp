#include "shared/desktop/core/security_materials.h"

#include "shared/desktop/core/app_metadata.h"
#include "shared/desktop/core/envelope_io.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QRandomGenerator>
#include <QtCore/QSaveFile>
#include <QtCore/QSet>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUuid>
#include <QtNetwork/QSslCertificate>
#include <QtProtobuf/QProtobufSerializer>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <exception>
#include <stdexcept>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_security_materials_log, "shared.desktop.core.security_materials")

namespace {

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

QString latest_openssl_error()
{
    const auto error = ERR_get_error();
    if (error == 0) {
        return QStringLiteral("OpenSSL operation failed");
    }

    char buffer[256]{};
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return QString::fromLatin1(buffer);
}

void ensure_openssl_success(const bool success, const QString &message)
{
    if (!success) {
        throw_security_error(message + QStringLiteral(": ") + latest_openssl_error());
    }
}

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using x509_req_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using bn_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using asn1_integer_ptr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

int cn_name_nid()
{
    return OBJ_txt2nid("CN");
}

evp_pkey_ptr load_private_key(const QString &path, const QString &context)
{
    QFile file{path};
    ensure_file_open(file, QIODevice::ReadOnly, context);

    const auto pem_data = file.readAll();
    bio_ptr bio{BIO_new_mem_buf(pem_data.constData(), static_cast<int>(pem_data.size())), BIO_free};
    if (bio == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to create BIO"));
    }

    evp_pkey_ptr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free};
    if (key == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to parse private key: ") + latest_openssl_error());
    }

    return key;
}

x509_ptr load_certificate_any_format(const QByteArray &data, const QString &context)
{
    bio_ptr pem_bio{BIO_new_mem_buf(data.constData(), static_cast<int>(data.size())), BIO_free};
    if (pem_bio == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to create BIO"));
    }

    if (auto *pem_cert = PEM_read_bio_X509(pem_bio.get(), nullptr, nullptr, nullptr); pem_cert != nullptr) {
        return x509_ptr{pem_cert, X509_free};
    }

    const unsigned char *der_data =
        reinterpret_cast<const unsigned char *>(data.constData());
    if (auto *der_cert = d2i_X509(nullptr, &der_data, data.size()); der_cert != nullptr) {
        return x509_ptr{der_cert, X509_free};
    }

    throw_security_error(context + QStringLiteral(": failed to parse certificate: ") + latest_openssl_error());
}

x509_ptr load_certificate(const QString &path, const QString &context)
{
    QFile file{path};
    ensure_file_open(file, QIODevice::ReadOnly, context);
    return load_certificate_any_format(file.readAll(), context);
}

x509_req_ptr load_csr_der(const QByteArray &der, const QString &context)
{
    const unsigned char *data =
        reinterpret_cast<const unsigned char *>(der.constData());
    x509_req_ptr request{d2i_X509_REQ(nullptr, &data, der.size()), X509_REQ_free};
    if (request == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to parse CSR: ") + latest_openssl_error());
    }

    return request;
}

void write_private_key_pem(EVP_PKEY *key, const QString &path, const QString &context)
{
    bio_ptr bio{BIO_new(BIO_s_mem()), BIO_free};
    if (bio == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to allocate output BIO"));
    }

    ensure_openssl_success(
        PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
        context + QStringLiteral(": failed to serialize private key"));

    BUF_MEM *buffer{};
    BIO_get_mem_ptr(bio.get(), &buffer);
    if (buffer == nullptr || buffer->data == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to read serialized private key"));
    }

    QSaveFile file{path};
    ensure_save_file_open(file, QIODevice::WriteOnly | QIODevice::Truncate, context);
    ensure_write(file, QByteArray{buffer->data, static_cast<qsizetype>(buffer->length)}, context);
    ensure_commit(file, context);
}

void write_x509_pem(X509 *certificate, const QString &path, const QString &context)
{
    bio_ptr bio{BIO_new(BIO_s_mem()), BIO_free};
    if (bio == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to allocate output BIO"));
    }

    ensure_openssl_success(
        PEM_write_bio_X509(bio.get(), certificate) == 1,
        context + QStringLiteral(": failed to serialize certificate"));

    BUF_MEM *buffer{};
    BIO_get_mem_ptr(bio.get(), &buffer);
    if (buffer == nullptr || buffer->data == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to read serialized certificate"));
    }

    QSaveFile file{path};
    ensure_save_file_open(file, QIODevice::WriteOnly | QIODevice::Truncate, context);
    ensure_write(file, QByteArray{buffer->data, static_cast<qsizetype>(buffer->length)}, context);
    ensure_commit(file, context);
}

void write_x509_der(X509 *certificate, const QString &path, const QString &context)
{
    const auto size = i2d_X509(certificate, nullptr);
    if (size <= 0) {
        throw_security_error(context + QStringLiteral(": failed to measure DER certificate"));
    }

    QByteArray der(size, Qt::Uninitialized);
    auto *output = reinterpret_cast<unsigned char *>(der.data());
    ensure_openssl_success(
        i2d_X509(certificate, &output) == size,
        context + QStringLiteral(": failed to serialize DER certificate"));

    QSaveFile file{path};
    ensure_save_file_open(file, QIODevice::WriteOnly | QIODevice::Truncate, context);
    ensure_write(file, der, context);
    ensure_commit(file, context);
}

void write_csr_der(X509_REQ *request, const QString &path, const QString &context)
{
    const auto size = i2d_X509_REQ(request, nullptr);
    if (size <= 0) {
        throw_security_error(context + QStringLiteral(": failed to measure DER CSR"));
    }

    QByteArray der(size, Qt::Uninitialized);
    auto *output = reinterpret_cast<unsigned char *>(der.data());
    ensure_openssl_success(
        i2d_X509_REQ(request, &output) == size,
        context + QStringLiteral(": failed to serialize DER CSR"));

    QSaveFile file{path};
    ensure_save_file_open(file, QIODevice::WriteOnly | QIODevice::Truncate, context);
    ensure_write(file, der, context);
    ensure_commit(file, context);
}

void set_subject_common_name(X509_NAME *name, const QString &common_name, const QString &context)
{
    const auto encoded_name = common_name.toUtf8();
    ensure_openssl_success(
        X509_NAME_add_entry_by_NID(
            name,
            cn_name_nid(),
            MBSTRING_UTF8,
            reinterpret_cast<const unsigned char *>(encoded_name.constData()),
            encoded_name.size(),
            -1,
            0) == 1,
        context + QStringLiteral(": failed to set certificate common name"));
}

void set_certificate_validity(X509 *certificate, const QString &context)
{
    ensure_openssl_success(
        X509_gmtime_adj(X509_getm_notBefore(certificate), -86400) != nullptr,
        context + QStringLiteral(": failed to set certificate not-before"));
    ensure_openssl_success(
        X509_gmtime_adj(X509_getm_notAfter(certificate), 36500LL * 24LL * 60LL * 60LL) != nullptr,
        context + QStringLiteral(": failed to set certificate not-after"));
}

void add_extension(X509 *certificate, X509 *issuer, const int nid, const char *value, const QString &context)
{
    X509V3_CTX extension_context{};
    X509V3_set_ctx(&extension_context, issuer, certificate, nullptr, nullptr, 0);
    auto *extension = X509V3_EXT_conf_nid(nullptr, &extension_context, nid, const_cast<char *>(value));
    if (extension == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to create X509 extension: ") + latest_openssl_error());
    }

    const auto extension_guard = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>(
        extension,
        X509_EXTENSION_free);
    ensure_openssl_success(
        X509_add_ext(certificate, extension_guard.get(), -1) == 1,
        context + QStringLiteral(": failed to add X509 extension"));
}

qulonglong next_certificate_serial(const QString &serial_path)
{
    qulonglong current_serial = 1;
    QFile file{serial_path};
    if (file.exists()) {
        ensure_file_open(file, QIODevice::ReadOnly, QStringLiteral("Failed to open CA serial file"));
        const auto text = file.readAll().trimmed();
        bool ok{};
        const auto parsed = text.toULongLong(&ok, 16);
        if (!ok || parsed == 0) {
            throw_security_error(QStringLiteral("Failed to parse CA serial file"));
        }
        current_serial = parsed;
    } else {
        current_serial = QRandomGenerator::system()->generate64();
        current_serial &= 0x7fffffffffffffffULL;
        if (current_serial == 0) {
            current_serial = 1;
        }
    }

    QSaveFile save_file{serial_path};
    ensure_save_file_open(
        save_file,
        QIODevice::WriteOnly | QIODevice::Truncate,
        QStringLiteral("Failed to open CA serial file for write"));
    const auto next_serial = QByteArray::number(current_serial + 1, 16).toUpper() + '\n';
    ensure_write(save_file, next_serial, QStringLiteral("Failed to write CA serial file"));
    ensure_commit(save_file, QStringLiteral("Failed to commit CA serial file"));

    return current_serial;
}

asn1_integer_ptr make_asn1_serial(const qulonglong serial, const QString &context)
{
    bn_ptr serial_bn{BN_new(), BN_free};
    if (serial_bn == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to allocate serial number"));
    }

    ensure_openssl_success(
        BN_set_word(serial_bn.get(), serial) == 1,
        context + QStringLiteral(": failed to set serial number"));

    asn1_integer_ptr serial_value{BN_to_ASN1_INTEGER(serial_bn.get(), nullptr), ASN1_INTEGER_free};
    if (serial_value == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to convert serial number"));
    }

    return serial_value;
}

evp_pkey_ptr generate_private_key(const char *algorithm, const char *group_name, const QString &context)
{
    evp_pkey_ctx_ptr context_ptr{
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr),
        EVP_PKEY_CTX_free};
    if (context_ptr == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to allocate key generation context"));
    }

    ensure_openssl_success(
        EVP_PKEY_keygen_init(context_ptr.get()) == 1,
        context + QStringLiteral(": failed to initialize key generation"));

    if (group_name != nullptr) {
        ensure_openssl_success(
            EVP_PKEY_CTX_set_group_name(context_ptr.get(), group_name) == 1,
            context + QStringLiteral(": failed to select key group"));
    }

    EVP_PKEY *generated_key{};
    ensure_openssl_success(
        EVP_PKEY_generate(context_ptr.get(), &generated_key) == 1,
        context + QStringLiteral(": failed to generate key"));

    return evp_pkey_ptr{generated_key, EVP_PKEY_free};
}

x509_req_ptr create_certificate_request(EVP_PKEY *key, const QString &common_name, const QString &context)
{
    x509_req_ptr request{X509_REQ_new(), X509_REQ_free};
    if (request == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to allocate CSR"));
    }

    ensure_openssl_success(
        X509_REQ_set_version(request.get(), 0L) == 1,
        context + QStringLiteral(": failed to set CSR version"));

    auto *subject = X509_REQ_get_subject_name(request.get());
    if (subject == nullptr) {
        throw_security_error(context + QStringLiteral(": failed to get CSR subject"));
    }
    set_subject_common_name(subject, common_name, context);

    ensure_openssl_success(
        X509_REQ_set_pubkey(request.get(), key) == 1,
        context + QStringLiteral(": failed to set CSR public key"));
    ensure_openssl_success(
        X509_REQ_sign(request.get(), key, EVP_sha256()) > 0,
        context + QStringLiteral(": failed to sign CSR"));

    return request;
}

}

security_materials::security_materials(const app_paths &app_paths)
    : app_paths_{app_paths}
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

    try {
        const auto key = load_private_key(
            app_paths_.peer_key_path(),
            QStringLiteral("Failed to load peer private key for enrollment CSR"));
        const auto request = create_certificate_request(
            key.get(),
            name,
            QStringLiteral("Failed to generate enrollment CSR"));
        write_csr_der(
            request.get(),
            app_paths_.peer_csr_der_path(),
            QStringLiteral("Failed to persist enrollment CSR"));
    } catch (const std::exception &exception) {
        result.error_message = QString::fromUtf8(exception.what());
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

        try {
            const auto certificate = load_certificate(
                app_paths_.peer_certificate_der_path(),
                QStringLiteral("Failed to load enrolled peer certificate"));
            write_x509_pem(
                certificate.get(),
                app_paths_.peer_certificate_path(),
                QStringLiteral("Failed to write enrolled peer certificate"));
        } catch (const std::exception &exception) {
            result.error_message = QString::fromUtf8(exception.what());
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

    const auto certificate_der_path = temporary_dir.filePath(QStringLiteral("peer-cert.der"));
    const auto certificate_pem_path = temporary_dir.filePath(QStringLiteral("peer-cert.pem"));

    try {
        const auto csr = load_csr_der(
            request.certificate_request,
            QStringLiteral("Failed to load enrollment CSR"));
        evp_pkey_ptr csr_public_key{X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free};
        if (csr_public_key == nullptr) {
            throw_security_error(QStringLiteral("Failed to extract enrollment CSR public key"));
        }
        ensure_openssl_success(
            X509_REQ_verify(csr.get(), csr_public_key.get()) == 1,
            QStringLiteral("Failed to verify enrollment CSR signature"));

        const auto ca_key = load_private_key(
            app_paths_.ca_key_path(),
            QStringLiteral("Failed to load trusted-agent CA private key"));
        const auto ca_certificate = load_certificate(
            app_paths_.ca_certificate_path(),
            QStringLiteral("Failed to load trusted-agent CA certificate"));

        x509_ptr certificate{X509_new(), X509_free};
        if (certificate == nullptr) {
            throw_security_error(QStringLiteral("Failed to allocate enrollment certificate"));
        }

        ensure_openssl_success(
            X509_set_version(certificate.get(), 2L) == 1,
            QStringLiteral("Failed to set enrollment certificate version"));
        const auto serial = make_asn1_serial(
            next_certificate_serial(app_paths_.ca_serial_path()),
            QStringLiteral("Failed to create enrollment certificate serial"));
        ensure_openssl_success(
            X509_set_serialNumber(certificate.get(), serial.get()) == 1,
            QStringLiteral("Failed to assign enrollment certificate serial"));
        set_certificate_validity(certificate.get(), QStringLiteral("Failed to set enrollment certificate validity"));
        ensure_openssl_success(
            X509_set_issuer_name(certificate.get(), X509_get_subject_name(ca_certificate.get())) == 1,
            QStringLiteral("Failed to set enrollment certificate issuer"));
        ensure_openssl_success(
            X509_set_subject_name(certificate.get(), X509_REQ_get_subject_name(csr.get())) == 1,
            QStringLiteral("Failed to set enrollment certificate subject"));
        ensure_openssl_success(
            X509_set_pubkey(certificate.get(), csr_public_key.get()) == 1,
            QStringLiteral("Failed to set enrollment certificate public key"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_basic_constraints,
            "critical,CA:FALSE",
            QStringLiteral("Failed to configure enrollment certificate basic constraints"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_key_usage,
            "critical,digitalSignature,keyAgreement",
            QStringLiteral("Failed to configure enrollment certificate key usage"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_ext_key_usage,
            "serverAuth,clientAuth",
            QStringLiteral("Failed to configure enrollment certificate extended key usage"));
        ensure_openssl_success(
            X509_sign(certificate.get(), ca_key.get(), EVP_sha256()) > 0,
            QStringLiteral("Failed to sign enrollment certificate"));

        write_x509_pem(
            certificate.get(),
            certificate_pem_path,
            QStringLiteral("Failed to write enrollment certificate PEM"));
        write_x509_der(
            certificate.get(),
            certificate_der_path,
            QStringLiteral("Failed to write enrollment certificate DER"));
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
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

security_materials::operation_result security_materials::remove_peer_from_current_peer_list(
    const agent_configuration &configuration,
    const QString &peer_id) const
{
    operation_result result{};
    const auto normalized_peer_id = peer_id.trimmed();
    if (configuration.role != agent_role::local_trusted_agent) {
        result.error_message = QStringLiteral("Only the trusted agent can remove authorized peers");
        return result;
    }

    if (normalized_peer_id.isEmpty()) {
        result.error_message = QStringLiteral("Peer id is required");
        return result;
    }

    if (normalized_peer_id == configuration.peer_id) {
        result.error_message = QStringLiteral("The trusted agent cannot remove itself");
        return result;
    }

    QString error_message{};
    auto current_peer_list = load_peer_list(error_message);
    if (!error_message.isEmpty()) {
        result.error_message = error_message;
        return result;
    }

    auto entries = current_peer_list.peers();
    auto removed = false;
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->identity().peerId().uuid() != normalized_peer_id) {
            continue;
        }

        qCInfo(shared_security_materials_log)
            << "Removing peer from signed peer list"
            << "peer_id=" << normalized_peer_id
            << "name=" << it->identity().name()
            << "current_version=" << current_peer_list.version();
        entries.erase(it);
        removed = true;
        break;
    }

    if (!removed) {
        result.error_message = QStringLiteral("Peer is not present in the signed peer list");
        return result;
    }

    shared::v1::PeerList next_peer_list{};
    next_peer_list.setVersion(current_peer_list.version() + 1);
    next_peer_list.setCreatedTimeMs(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());
    next_peer_list.setTrustedAgentPeerId(current_peer_list.trustedAgentPeerId());
    next_peer_list.setPeers(entries);

    if (!validate_peer_entries(next_peer_list.peers(), error_message)) {
        result.error_message = error_message;
        return result;
    }

    shared::v1::PeerListToSign peer_list_to_sign{};
    peer_list_to_sign.setVersion(next_peer_list.version());
    peer_list_to_sign.setCreatedTimeMs(next_peer_list.createdTimeMs());
    peer_list_to_sign.setTrustedAgentPeerId(next_peer_list.trustedAgentPeerId());
    peer_list_to_sign.setPeers(next_peer_list.peers());

    const auto signature = sign_peer_list_payload(peer_list_to_sign, error_message);
    if (signature.isEmpty()) {
        result.error_message = error_message;
        return result;
    }

    next_peer_list.setSignature(signature);
    next_peer_list.setSignatureAlgorithm(QStringLiteral("sha256-ecdsa"));

    if (!write_peer_list(next_peer_list, error_message)) {
        result.error_message = error_message;
        return result;
    }

    qCInfo(shared_security_materials_log)
        << "Removed peer from signed peer list"
        << "peer_id=" << normalized_peer_id
        << "new_version=" << next_peer_list.version();
    result.success = true;
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
    try {
        const auto key = generate_private_key(
            "EC",
            "prime256v1",
            QStringLiteral("Failed to generate EC private key"));
        write_private_key_pem(key.get(), path, QStringLiteral("Failed to write EC private key"));
        return true;
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return false;
    }
}

bool security_materials::generate_x25519_private_key(const QString &path, QString &error_message) const
{
    try {
        const auto key = generate_private_key(
            "X25519",
            nullptr,
            QStringLiteral("Failed to generate X25519 private key"));
        write_private_key_pem(key.get(), path, QStringLiteral("Failed to write X25519 private key"));
        return true;
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return false;
    }
}

bool security_materials::generate_self_signed_ca(QString &error_message) const
{
    try {
        const auto key = load_private_key(
            app_paths_.ca_key_path(),
            QStringLiteral("Failed to load CA private key"));
        x509_ptr certificate{X509_new(), X509_free};
        if (certificate == nullptr) {
            throw_security_error(QStringLiteral("Failed to allocate CA certificate"));
        }

        ensure_openssl_success(
            X509_set_version(certificate.get(), 2L) == 1,
            QStringLiteral("Failed to set CA certificate version"));
        const auto serial = make_asn1_serial(1, QStringLiteral("Failed to create CA certificate serial"));
        ensure_openssl_success(
            X509_set_serialNumber(certificate.get(), serial.get()) == 1,
            QStringLiteral("Failed to assign CA certificate serial"));
        set_certificate_validity(certificate.get(), QStringLiteral("Failed to set CA certificate validity"));

        auto *subject = X509_get_subject_name(certificate.get());
        if (subject == nullptr) {
            throw_security_error(QStringLiteral("Failed to get CA certificate subject"));
        }
        set_subject_common_name(
            subject,
            QStringLiteral("shared-trusted-agent-ca"),
            QStringLiteral("Failed to set CA certificate subject"));
        ensure_openssl_success(
            X509_set_issuer_name(certificate.get(), subject) == 1,
            QStringLiteral("Failed to set CA certificate issuer"));
        ensure_openssl_success(
            X509_set_pubkey(certificate.get(), key.get()) == 1,
            QStringLiteral("Failed to set CA certificate public key"));
        add_extension(
            certificate.get(),
            certificate.get(),
            NID_basic_constraints,
            "critical,CA:TRUE",
            QStringLiteral("Failed to configure CA certificate basic constraints"));
        add_extension(
            certificate.get(),
            certificate.get(),
            NID_key_usage,
            "critical,keyCertSign,cRLSign",
            QStringLiteral("Failed to configure CA certificate key usage"));
        add_extension(
            certificate.get(),
            certificate.get(),
            NID_subject_key_identifier,
            "hash",
            QStringLiteral("Failed to configure CA certificate subject key identifier"));
        ensure_openssl_success(
            X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0,
            QStringLiteral("Failed to self-sign CA certificate"));

        write_x509_pem(
            certificate.get(),
            app_paths_.ca_certificate_path(),
            QStringLiteral("Failed to write CA certificate"));
        return true;
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return false;
    }
}

bool security_materials::generate_signed_certificate(
    const QString &key_path,
    const QString &certificate_path,
    const QString &certificate_der_path,
    const QString &subject_common_name,
    QString &error_message,
    const QString &csr_der_path) const
{
    try {
        const auto leaf_key = load_private_key(key_path, QStringLiteral("Failed to load leaf private key"));
        const auto request = create_certificate_request(
            leaf_key.get(),
            subject_common_name,
            QStringLiteral("Failed to create certificate request"));

        if (!csr_der_path.isEmpty()) {
            write_csr_der(
                request.get(),
                csr_der_path,
                QStringLiteral("Failed to write certificate request"));
        }

        evp_pkey_ptr request_public_key{X509_REQ_get_pubkey(request.get()), EVP_PKEY_free};
        if (request_public_key == nullptr) {
            throw_security_error(QStringLiteral("Failed to extract certificate request public key"));
        }

        const auto ca_key = load_private_key(
            app_paths_.ca_key_path(),
            QStringLiteral("Failed to load CA private key for certificate signing"));
        const auto ca_certificate = load_certificate(
            app_paths_.ca_certificate_path(),
            QStringLiteral("Failed to load CA certificate for certificate signing"));

        x509_ptr certificate{X509_new(), X509_free};
        if (certificate == nullptr) {
            throw_security_error(QStringLiteral("Failed to allocate signed certificate"));
        }

        ensure_openssl_success(
            X509_set_version(certificate.get(), 2L) == 1,
            QStringLiteral("Failed to set signed certificate version"));
        const auto serial = make_asn1_serial(
            next_certificate_serial(app_paths_.ca_serial_path()),
            QStringLiteral("Failed to create signed certificate serial"));
        ensure_openssl_success(
            X509_set_serialNumber(certificate.get(), serial.get()) == 1,
            QStringLiteral("Failed to assign signed certificate serial"));
        set_certificate_validity(certificate.get(), QStringLiteral("Failed to set signed certificate validity"));
        ensure_openssl_success(
            X509_set_issuer_name(certificate.get(), X509_get_subject_name(ca_certificate.get())) == 1,
            QStringLiteral("Failed to set signed certificate issuer"));
        ensure_openssl_success(
            X509_set_subject_name(certificate.get(), X509_REQ_get_subject_name(request.get())) == 1,
            QStringLiteral("Failed to set signed certificate subject"));
        ensure_openssl_success(
            X509_set_pubkey(certificate.get(), request_public_key.get()) == 1,
            QStringLiteral("Failed to set signed certificate public key"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_basic_constraints,
            "critical,CA:FALSE",
            QStringLiteral("Failed to configure signed certificate basic constraints"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_key_usage,
            "critical,digitalSignature,keyAgreement",
            QStringLiteral("Failed to configure signed certificate key usage"));
        add_extension(
            certificate.get(),
            ca_certificate.get(),
            NID_ext_key_usage,
            "serverAuth,clientAuth",
            QStringLiteral("Failed to configure signed certificate extended key usage"));
        ensure_openssl_success(
            X509_sign(certificate.get(), ca_key.get(), EVP_sha256()) > 0,
            QStringLiteral("Failed to sign certificate"));

        write_x509_pem(
            certificate.get(),
            certificate_path,
            QStringLiteral("Failed to write signed certificate PEM"));
        write_x509_der(
            certificate.get(),
            certificate_der_path,
            QStringLiteral("Failed to write signed certificate DER"));
        return true;
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return false;
    }
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
    QProtobufSerializer serializer{};
    const auto payload = peer_list_to_sign.serialize(&serializer);

    try {
        const auto key = load_private_key(
            app_paths_.ca_key_path(),
            QStringLiteral("Failed to load CA private key for peer-list signing"));
        evp_md_ctx_ptr context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
        if (context == nullptr) {
            throw_security_error(QStringLiteral("Failed to allocate peer-list signing context"));
        }

        ensure_openssl_success(
            EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1,
            QStringLiteral("Failed to initialize peer-list signing"));
        ensure_openssl_success(
            EVP_DigestSignUpdate(context.get(), payload.constData(), static_cast<size_t>(payload.size())) == 1,
            QStringLiteral("Failed to feed peer-list payload into signing"));

        size_t signature_size{};
        ensure_openssl_success(
            EVP_DigestSignFinal(context.get(), nullptr, &signature_size) == 1,
            QStringLiteral("Failed to measure peer-list signature"));

        QByteArray signature(static_cast<qsizetype>(signature_size), Qt::Uninitialized);
        ensure_openssl_success(
            EVP_DigestSignFinal(
                context.get(),
                reinterpret_cast<unsigned char *>(signature.data()),
                &signature_size) == 1,
            QStringLiteral("Failed to finalize peer-list signature"));
        signature.resize(static_cast<qsizetype>(signature_size));
        return signature;
    } catch (const std::exception &exception) {
        error_message = QString::fromUtf8(exception.what());
        return {};
    }
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
