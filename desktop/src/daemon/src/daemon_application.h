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
