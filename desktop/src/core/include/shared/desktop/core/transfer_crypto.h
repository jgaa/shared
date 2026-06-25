#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace shared::desktop::core {

class app_paths;

class transfer_crypto {
public:
    struct encrypted_payload {
        QByteArray ciphertext{};
        QByteArray nonce{};
        QByteArray auth_tag{};
    };

    static constexpr int payload_key_size{32};
    static constexpr int gcm_nonce_size{12};
    static constexpr int gcm_auth_tag_size{16};

    [[nodiscard]] static QByteArray random_bytes(int count, QString &error_message);
    [[nodiscard]] static QByteArray sha256_hex(const QByteArray &payload);
    [[nodiscard]] static encrypted_payload encrypt_aes_gcm(
        const QByteArray &key,
        const QByteArray &plaintext,
        QString &error_message);
    [[nodiscard]] static QByteArray decrypt_aes_gcm(
        const QByteArray &key,
        const encrypted_payload &payload,
        QString &error_message);
    [[nodiscard]] static QByteArray wrap_payload_key_for_recipient(
        const app_paths &app_paths,
        const QByteArray &recipient_public_key,
        const QByteArray &payload_key,
        QString &error_message);
    [[nodiscard]] static QByteArray unwrap_payload_key_from_sender(
        const app_paths &app_paths,
        const QByteArray &sender_public_key,
        const QByteArray &wrapped_payload_key,
        QString &error_message);
};

}
