#pragma once

#include "shared/desktop/core/configuration_repository.h"
#include "shared/desktop/core/pending_enrollment_repository.h"
#include "shared/desktop/core/security_materials.h"

#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QUuid>
#include <QtNetwork/QSslServer>
#include <QtNetwork/QSslSocket>

namespace shared::desktop::daemon {

class enrollment_server final : public QObject {
    Q_OBJECT

public:
    enrollment_server(
        const core::agent_configuration &configuration,
        const core::app_paths &app_paths,
        QObject *parent = nullptr);

    [[nodiscard]] bool start(QString &error_message);
    void stop();

private:
    struct session_state {
        QByteArray buffer{};
        QString request_id{};
    };

    void handle_pending_connection();
    void handle_socket_ready_read(QSslSocket *socket);
    void maybe_finish_request(QSslSocket *socket);
    void close_socket(QSslSocket *socket);

    core::agent_configuration configuration_{};
    core::app_paths app_paths_{};
    core::pending_enrollment_repository pending_enrollment_repository_;
    core::security_materials security_materials_;
    QSslServer server_{};
    QHash<QSslSocket *, session_state> sessions_{};
};

}
