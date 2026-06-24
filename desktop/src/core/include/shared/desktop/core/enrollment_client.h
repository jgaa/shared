#pragma once

#include "shared/desktop/core/agent_configuration.h"
#include "shared/desktop/core/security_materials.h"

#include <QtCore/QString>

namespace shared::desktop::core {

class app_paths;
class configuration_repository;
class enrollment_client {
public:
    struct result {
        bool success{};
        QString error_message{};
        QString verification_code{};
    };

    enrollment_client(
        const app_paths &app_paths,
        configuration_repository &configuration_repository,
        security_materials &security_materials);

    [[nodiscard]] result enroll(
        const QString &name,
        const QString &host,
        quint16 port,
        const QString &expected_server_fingerprint);

    [[nodiscard]] result enroll_prepared(
        const QString &name,
        const security_materials::prepared_enrollment &prepared,
        const QString &host,
        quint16 port,
        const QString &expected_server_fingerprint);

private:
    const app_paths &app_paths_;
    configuration_repository &configuration_repository_;
    security_materials &security_materials_;
};

}
