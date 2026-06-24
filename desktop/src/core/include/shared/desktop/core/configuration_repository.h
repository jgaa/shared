#pragma once

#include "shared/desktop/core/agent_configuration.h"

namespace shared::desktop::core {

class configuration_repository {
public:
    configuration_repository();

    [[nodiscard]] agent_configuration load() const;
    void save(const agent_configuration &configuration);

private:
    [[nodiscard]] QString role_to_string(agent_role role) const;
    [[nodiscard]] agent_role role_from_string(const QString &value) const;
};

}
