#pragma once

#include <QtCore/QMetaType>
#include <QtCore/QString>

namespace shared::desktop::core {

enum class agent_role {
    unconfigured,
    local_trusted_agent,
    peer,
};

struct trusted_agent_endpoint {
    QString host{};
    quint16 port{};
    QString pinned_server_fingerprint{};
};

struct agent_configuration {
    bool initialized{};
    agent_role role{agent_role::unconfigured};
    QString peer_id{};
    QString name{};
    quint16 enrollment_port{47123};
    trusted_agent_endpoint trusted_agent{};
};

struct pending_enrollment_request {
    QString request_id{};
    QString peer_id{};
    QString name{};
    QString verification_code{};
    QByteArray certificate_request{};
    QByteArray x25519_public_key{};
    qint64 created_time_ms{};
};

struct pending_enrollment_decision {
    bool decided{};
    bool approved{};
    QString message{};
};

}
