#include "shared/desktop/core/transfer_crypto.h"

#include "shared/desktop/core/app_paths.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <array>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_transfer_crypto_log, "shared.desktop.core.transfer_crypto")

namespace {

constexpr auto wrapping_info = std::to_array<unsigned char>({
    's', 'h', 'a', 'r', 'e', 'd', '-', 't', 'r', 'a', 'n', 's',
    'f', 'e', 'r', '-', 'k', 'e', 'y', '-', 'w', 'r', 'a', 'p', '-', 'v', '1'
});

QByteArray read_file_bytes(const QString &path, QString &error_message)
{
    QFile file{path};
    if (!file.open(QIODevice::ReadOnly)) {
        error_message = QStringLiteral("Failed to open key file %1: %2").arg(path, file.errorString());
        return {};
    }

    return file.readAll();
}

EVP_PKEY *load_local_x25519_private_key(const QString &path, QString &error_message)
{
    const auto pem_data = read_file_bytes(path, error_message);
    if (pem_data.isEmpty()) {
        return nullptr;
    }

    BIO *bio = BIO_new_mem_buf(pem_data.constData(), static_cast<int>(pem_data.size()));
    if (bio == nullptr) {
        error_message = QStringLiteral("Failed to create BIO for local X25519 private key");
        return nullptr;
    }

    EVP_PKEY *private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (private_key == nullptr) {
        error_message = QStringLiteral("Failed to parse local X25519 private key");
        return nullptr;
    }

    return private_key;
}

EVP_PKEY *load_remote_x25519_public_key(const QByteArray &public_key_bytes, QString &error_message)
{
    if (public_key_bytes.size() != 32) {
        error_message = QStringLiteral("Remote X25519 public key must be 32 bytes");
        return nullptr;
    }

    EVP_PKEY *public_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char *>(public_key_bytes.constData()),
        static_cast<size_t>(public_key_bytes.size()));
    if (public_key == nullptr) {
        error_message = QStringLiteral("Failed to load remote X25519 public key");
        return nullptr;
    }

    return public_key;
}

QByteArray derive_shared_secret(EVP_PKEY *private_key, EVP_PKEY *public_key, QString &error_message)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(private_key, nullptr);
    if (context == nullptr) {
        error_message = QStringLiteral("Failed to allocate X25519 derive context");
        return {};
    }

    QByteArray secret{};
    do {
        if (EVP_PKEY_derive_init(context) != 1) {
            error_message = QStringLiteral("Failed to initialize X25519 derivation");
            break;
        }
        if (EVP_PKEY_derive_set_peer(context, public_key) != 1) {
            error_message = QStringLiteral("Failed to set X25519 peer key");
            break;
        }

        size_t secret_size{};
        if (EVP_PKEY_derive(context, nullptr, &secret_size) != 1) {
            error_message = QStringLiteral("Failed to measure X25519 shared secret");
            break;
        }

        secret.resize(static_cast<qsizetype>(secret_size));
        if (EVP_PKEY_derive(
                context,
                reinterpret_cast<unsigned char *>(secret.data()),
                &secret_size) != 1) {
            error_message = QStringLiteral("Failed to derive X25519 shared secret");
            secret.clear();
            break;
        }
        secret.resize(static_cast<qsizetype>(secret_size));
    } while (false);

    EVP_PKEY_CTX_free(context);
    return secret;
}

QByteArray hkdf_sha256(const QByteArray &secret, QString &error_message)
{
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) {
        error_message = QStringLiteral("Failed to fetch HKDF implementation");
        return {};
    }

    EVP_KDF_CTX *context = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (context == nullptr) {
        error_message = QStringLiteral("Failed to allocate HKDF context");
        return {};
    }

    QByteArray output(transfer_crypto::payload_key_size, Qt::Uninitialized);
    const auto mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            const_cast<char *>("digest"),
            const_cast<char *>("SHA256"),
            0),
        OSSL_PARAM_construct_octet_string(
            const_cast<char *>("key"),
            const_cast<char *>(secret.data()),
            static_cast<size_t>(secret.size())),
        OSSL_PARAM_construct_octet_string(
            const_cast<char *>("info"),
            const_cast<unsigned char *>(wrapping_info.data()),
            wrapping_info.size()),
        OSSL_PARAM_construct_int(const_cast<char *>("mode"), const_cast<int *>(&mode)),
        OSSL_PARAM_construct_end(),
    };

    if (EVP_KDF_derive(
            context,
            reinterpret_cast<unsigned char *>(output.data()),
            static_cast<size_t>(output.size()),
            params) != 1) {
        error_message = QStringLiteral("Failed to derive HKDF-SHA256 wrapping key");
        output.clear();
    }

    EVP_KDF_CTX_free(context);
    return output;
}

transfer_crypto::encrypted_payload encrypt_internal(
    const QByteArray &key,
    const QByteArray &plaintext,
    QString &error_message)
{
    transfer_crypto::encrypted_payload result{};
    if (key.size() != transfer_crypto::payload_key_size) {
        error_message = QStringLiteral("AES-256-GCM key must be 32 bytes");
        return result;
    }

    result.nonce = transfer_crypto::random_bytes(transfer_crypto::gcm_nonce_size, error_message);
    if (result.nonce.isEmpty()) {
        return result;
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        error_message = QStringLiteral("Failed to allocate AES-GCM context");
        result.nonce.clear();
        return result;
    }

    int output_length{};
    int total_length{};
    result.ciphertext.resize(plaintext.size());
    result.auth_tag.resize(transfer_crypto::gcm_auth_tag_size);

    auto success = false;
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_IVLEN,
            result.nonce.size(),
            nullptr) == 1
        && EVP_EncryptInit_ex(
            context,
            nullptr,
            nullptr,
            reinterpret_cast<const unsigned char *>(key.constData()),
            reinterpret_cast<const unsigned char *>(result.nonce.constData())) == 1
        && EVP_EncryptUpdate(
            context,
            reinterpret_cast<unsigned char *>(result.ciphertext.data()),
            &output_length,
            reinterpret_cast<const unsigned char *>(plaintext.constData()),
            plaintext.size()) == 1) {
        total_length = output_length;
        if (EVP_EncryptFinal_ex(
                context,
                reinterpret_cast<unsigned char *>(result.ciphertext.data()) + total_length,
                &output_length) == 1
            && EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_GET_TAG,
                result.auth_tag.size(),
                result.auth_tag.data()) == 1) {
            total_length += output_length;
            result.ciphertext.resize(total_length);
            success = true;
        }
    }

    EVP_CIPHER_CTX_free(context);
    if (!success) {
        error_message = QStringLiteral("Failed to encrypt payload with AES-256-GCM");
        result = {};
    }

    return result;
}

QByteArray decrypt_internal(
    const QByteArray &key,
    const transfer_crypto::encrypted_payload &payload,
    QString &error_message)
{
    if (key.size() != transfer_crypto::payload_key_size) {
        error_message = QStringLiteral("AES-256-GCM key must be 32 bytes");
        return {};
    }

    if (payload.nonce.size() != transfer_crypto::gcm_nonce_size
        || payload.auth_tag.size() != transfer_crypto::gcm_auth_tag_size) {
        error_message = QStringLiteral("Invalid AES-GCM payload framing");
        return {};
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        error_message = QStringLiteral("Failed to allocate AES-GCM context");
        return {};
    }

    QByteArray plaintext(payload.ciphertext.size(), Qt::Uninitialized);
    int output_length{};
    int total_length{};
    auto success = false;

    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_IVLEN,
            payload.nonce.size(),
            nullptr) == 1
        && EVP_DecryptInit_ex(
            context,
            nullptr,
            nullptr,
            reinterpret_cast<const unsigned char *>(key.constData()),
            reinterpret_cast<const unsigned char *>(payload.nonce.constData())) == 1
        && EVP_DecryptUpdate(
            context,
            reinterpret_cast<unsigned char *>(plaintext.data()),
            &output_length,
            reinterpret_cast<const unsigned char *>(payload.ciphertext.constData()),
            payload.ciphertext.size()) == 1) {
        total_length = output_length;
        if (EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_SET_TAG,
                payload.auth_tag.size(),
                const_cast<char *>(payload.auth_tag.constData())) == 1
            && EVP_DecryptFinal_ex(
                context,
                reinterpret_cast<unsigned char *>(plaintext.data()) + total_length,
                &output_length) == 1) {
            total_length += output_length;
            plaintext.resize(total_length);
            success = true;
        }
    }

    EVP_CIPHER_CTX_free(context);
    if (!success) {
        error_message = QStringLiteral("Failed to decrypt AES-256-GCM payload");
        return {};
    }

    return plaintext;
}

}

QByteArray transfer_crypto::random_bytes(int count, QString &error_message)
{
    if (count <= 0) {
        error_message = QStringLiteral("Random byte count must be positive");
        return {};
    }

    QByteArray output(count, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(output.data()), count) != 1) {
        error_message = QStringLiteral("Failed to generate random bytes");
        qCCritical(shared_transfer_crypto_log) << error_message;
        return {};
    }

    return output;
}

QByteArray transfer_crypto::sha256_hex(const QByteArray &payload)
{
    return QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex();
}

transfer_crypto::encrypted_payload transfer_crypto::encrypt_aes_gcm(
    const QByteArray &key,
    const QByteArray &plaintext,
    QString &error_message)
{
    return encrypt_internal(key, plaintext, error_message);
}

QByteArray transfer_crypto::decrypt_aes_gcm(
    const QByteArray &key,
    const encrypted_payload &payload,
    QString &error_message)
{
    return decrypt_internal(key, payload, error_message);
}

QByteArray transfer_crypto::wrap_payload_key_for_recipient(
    const app_paths &app_paths,
    const QByteArray &recipient_public_key,
    const QByteArray &payload_key,
    QString &error_message)
{
    EVP_PKEY *private_key = load_local_x25519_private_key(app_paths.x25519_private_key_path(), error_message);
    if (private_key == nullptr) {
        return {};
    }

    EVP_PKEY *public_key = load_remote_x25519_public_key(recipient_public_key, error_message);
    if (public_key == nullptr) {
        EVP_PKEY_free(private_key);
        return {};
    }

    const auto shared_secret = derive_shared_secret(private_key, public_key, error_message);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    if (shared_secret.isEmpty()) {
        return {};
    }

    const auto wrapping_key = hkdf_sha256(shared_secret, error_message);
    if (wrapping_key.isEmpty()) {
        return {};
    }

    const auto encrypted_key = encrypt_internal(wrapping_key, payload_key, error_message);
    if (encrypted_key.ciphertext.isEmpty()) {
        return {};
    }

    QByteArray wrapped{};
    wrapped.reserve(
        encrypted_key.nonce.size()
        + encrypted_key.auth_tag.size()
        + encrypted_key.ciphertext.size());
    wrapped.append(encrypted_key.nonce);
    wrapped.append(encrypted_key.auth_tag);
    wrapped.append(encrypted_key.ciphertext);
    return wrapped;
}

QByteArray transfer_crypto::unwrap_payload_key_from_sender(
    const app_paths &app_paths,
    const QByteArray &sender_public_key,
    const QByteArray &wrapped_payload_key,
    QString &error_message)
{
    if (wrapped_payload_key.size() < gcm_nonce_size + gcm_auth_tag_size + payload_key_size) {
        error_message = QStringLiteral("Wrapped payload key is too small");
        return {};
    }

    EVP_PKEY *private_key = load_local_x25519_private_key(app_paths.x25519_private_key_path(), error_message);
    if (private_key == nullptr) {
        return {};
    }

    EVP_PKEY *public_key = load_remote_x25519_public_key(sender_public_key, error_message);
    if (public_key == nullptr) {
        EVP_PKEY_free(private_key);
        return {};
    }

    const auto shared_secret = derive_shared_secret(private_key, public_key, error_message);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    if (shared_secret.isEmpty()) {
        return {};
    }

    const auto wrapping_key = hkdf_sha256(shared_secret, error_message);
    if (wrapping_key.isEmpty()) {
        return {};
    }

    encrypted_payload wrapped{};
    wrapped.nonce = wrapped_payload_key.first(gcm_nonce_size);
    wrapped.auth_tag = wrapped_payload_key.mid(gcm_nonce_size, gcm_auth_tag_size);
    wrapped.ciphertext = wrapped_payload_key.mid(gcm_nonce_size + gcm_auth_tag_size);
    return decrypt_internal(wrapping_key, wrapped, error_message);
}

}
