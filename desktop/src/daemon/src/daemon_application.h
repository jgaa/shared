#pragma once

#include "enrollment_server.h"
#include "peer_service.h"

#include "shared/desktop/core/app_paths.h"
#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/settings_repository.h"

#include <QtCore/QObject>
#include <QtCore/QTimer>
#include <memory>

namespace shared::desktop::daemon {

class daemon_application final : public QObject {
    Q_OBJECT

public:
    explicit daemon_application(QObject *parent = nullptr);

    [[nodiscard]] bool start();
    void apply_configuration_change();
    [[nodiscard]] bool send_clipboard_text(
        const QStringList &peer_ids,
        const QString &text,
        QString &error_message);
    [[nodiscard]] bool send_files(
        const QStringList &peer_ids,
        const QStringList &file_paths,
        QString &error_message);
    [[nodiscard]] bool approve_clipboard_transfer(const QString &transfer_id, QString &error_message);
    [[nodiscard]] bool reject_clipboard_transfer(
        const QString &transfer_id,
        const QString &message,
        QString &error_message);
    [[nodiscard]] bool approve_file_transfer(const QString &transfer_id, QString &error_message);
    [[nodiscard]] bool reject_file_transfer(
        const QString &transfer_id,
        const QString &message,
        QString &error_message);

signals:
    void clipboard_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        quint64 size_bytes);
    void clipboard_text_received(const QString &sender_peer_id, const QString &sender_name, const QString &text);
    void clipboard_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);
    void file_approval_requested(
        const QString &transfer_id,
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        quint64 size_bytes);
    void file_received(
        const QString &sender_peer_id,
        const QString &sender_name,
        const QString &filename,
        const QString &saved_path,
        quint64 size_bytes);
    void file_transfer_status(
        const QString &transfer_id,
        const QString &peer_id,
        const QString &peer_name,
        int status,
        const QString &message);

private slots:
    void reload_configuration();

private:
    [[nodiscard]] bool configurations_match(
        const core::agent_configuration &left,
        const core::agent_configuration &right) const;

    core::app_paths app_paths_{};
    core::configuration_repository configuration_repository_{};
    core::settings_repository settings_repository_{};
    core::agent_configuration configuration_{};
    std::unique_ptr<enrollment_server> enrollment_server_{};
    std::unique_ptr<peer_service> peer_service_{};
    QTimer configuration_reload_timer_{};
};

}
