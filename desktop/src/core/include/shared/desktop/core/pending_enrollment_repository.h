#pragma once

#include "shared/desktop/core/agent_configuration.h"
#include "shared/desktop/core/app_paths.h"

#include <optional>

namespace shared::desktop::core {

class pending_enrollment_repository {
public:
    explicit pending_enrollment_repository(const app_paths &app_paths);

    void save_request(const pending_enrollment_request &request) const;
    [[nodiscard]] QList<pending_enrollment_request> load_requests() const;
    [[nodiscard]] std::optional<pending_enrollment_request> load_request(const QString &request_id) const;

    void save_decision(
        const QString &request_id,
        bool approved,
        const QString &message) const;

    [[nodiscard]] std::optional<pending_enrollment_decision> load_decision(const QString &request_id) const;
    void remove_request(const QString &request_id) const;

private:
    [[nodiscard]] QString request_path(const QString &request_id) const;
    [[nodiscard]] QString decision_path(const QString &request_id) const;

    const app_paths &app_paths_;
};

}
