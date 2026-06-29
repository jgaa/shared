#pragma once

#include "shared/desktop/core/agent_configuration.h"
#include "shared/desktop/core/app_paths.h"
#include "shared.qpb.h"

#include <QtCore/QByteArray>
#include <QtCore/QHash>
#include <QtNetwork/QSslCertificate>

#include <QtCore/QString>

namespace shared::desktop::core {

class configuration_repository;

class security_materials {
public:
    struct operation_result {
        bool success{};
        QString error_message{};
    };

    struct trusted_agent_init_result : operation_result {
        QString peer_id{};
        QString enrollment_fingerprint{};
    };

    struct prepared_enrollment {
        bool success{};
        QString error_message{};
        QString peer_id{};
        QString verification_code{};
        shared::v1::EnrollmentRequest request{};
    };

    struct peer_list_update_result : operation_result {
        bool updated{};
    };

    explicit security_materials(const app_paths &app_paths);

    [[nodiscard]] operation_result ensure_runtime_materials() const;
    [[nodiscard]] operation_result reset_local_agent_state() const;

    [[nodiscard]] trusted_agent_init_result initialize_local_trusted_agent(
        const QString &name,
        quint16 enrollment_port) const;

    [[nodiscard]] prepared_enrollment prepare_enrollment_request(
        const QString &name) const;

    [[nodiscard]] operation_result finalize_enrollment(
        const agent_configuration &configuration,
        const shared::v1::EnrollmentDecision &decision) const;

    [[nodiscard]] operation_result write_rejection_marker(
        const QString &message) const;

    [[nodiscard]] shared::v1::EnrollmentDecision build_approved_decision(
        const agent_configuration &configuration,
        const pending_enrollment_request &request,
        QString &error_message) const;

    [[nodiscard]] QString current_server_enrollment_fingerprint() const;
    [[nodiscard]] QByteArray current_ca_certificate_der() const;
    [[nodiscard]] QByteArray current_ca_certificate_pem(QString &error_message) const;
    [[nodiscard]] QByteArray current_peer_certificate_pem(QString &error_message) const;
    [[nodiscard]] QByteArray current_peer_private_key_pem(QString &error_message) const;
    [[nodiscard]] QByteArray current_server_certificate_pem(QString &error_message) const;
    [[nodiscard]] QByteArray current_server_private_key_pem(QString &error_message) const;
    [[nodiscard]] QByteArray current_pinned_trusted_agent_ca_certificate_der(QString &error_message) const;
    [[nodiscard]] QByteArray current_x25519_private_key_pem(QString &error_message) const;
    [[nodiscard]] shared::v1::PeerList current_peer_list(QString &error_message) const;
    [[nodiscard]] peer_list_update_result store_peer_list_if_newer(
        const shared::v1::PeerList &peer_list) const;
    [[nodiscard]] operation_result remove_peer_from_current_peer_list(
        const agent_configuration &configuration,
        const QString &peer_id) const;
    [[nodiscard]] bool validate_peer_list(
        const shared::v1::PeerList &peer_list,
        QString &error_message) const;
    [[nodiscard]] bool is_known_peer_identity(
        const QString &peer_id,
        const QString &peer_name,
        const QString &certificate_fingerprint_sha256,
        QString &error_message) const;
    [[nodiscard]] static QString certificate_fingerprint_sha256(const QSslCertificate &certificate);
    [[nodiscard]] static QString normalize_enrollment_fingerprint(const QString &value);
    [[nodiscard]] static QString format_enrollment_fingerprint(const QString &value);

private:
    [[nodiscard]] bool write_peer_list(
        const shared::v1::PeerList &peer_list,
        QString &error_message) const;

    [[nodiscard]] shared::v1::PeerList load_peer_list(QString &error_message) const;
    [[nodiscard]] shared::v1::PeerList create_or_update_peer_list(
        const agent_configuration &configuration,
        const pending_enrollment_request *request,
        const QByteArray &request_certificate_pem,
        QString &error_message) const;

    [[nodiscard]] QByteArray sign_peer_list_payload(
        const shared::v1::PeerListToSign &peer_list_to_sign,
        QString &error_message) const;

    [[nodiscard]] QByteArray raw_x25519_public_key(const QByteArray &private_key_pem, QString &error_message) const;
    [[nodiscard]] QString certificate_fingerprint(const QByteArray &certificate_bytes, QString &error_message) const;
    [[nodiscard]] QString enrollment_fingerprint(const QByteArray &certificate_bytes, QString &error_message) const;
    [[nodiscard]] QByteArray certificate_der(const QByteArray &certificate_bytes, QString &error_message) const;
    [[nodiscard]] qint64 certificate_not_before_ms(const QByteArray &certificate_bytes, QString &error_message) const;
    [[nodiscard]] qint64 certificate_not_after_ms(const QByteArray &certificate_bytes, QString &error_message) const;
    [[nodiscard]] QString verification_code_for_csr(const QByteArray &csr_der) const;
    [[nodiscard]] QString uuid_v7_string() const;
    [[nodiscard]] shared::v1::PeerListEntry local_peer_list_entry(
        const agent_configuration &configuration,
        QString &error_message) const;
    [[nodiscard]] shared::v1::PeerListEntry peer_list_entry_for_request(
        const pending_enrollment_request &request,
        const QByteArray &certificate_pem,
        QString &error_message) const;
    [[nodiscard]] QByteArray load_secret_bytes_cached(
        const char *name,
        const char *description,
        QString &error_message) const;
    [[nodiscard]] bool store_secret_bytes_cached(
        const char *name,
        const char *description,
        const QByteArray &bytes,
        QString &error_message) const;
    [[nodiscard]] bool remove_secret_cached(const char *name, QString &error_message) const;
    void clear_secret_cache() const;

    const app_paths &app_paths_;
};

}
