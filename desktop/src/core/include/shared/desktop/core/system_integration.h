#pragma once

#include "shared.qpb.h"
#include <QtCore/QSettings>

namespace shared::desktop::core::system_integration {

[[nodiscard]] shared::v1::PlatformGadget::Platform current_platform() noexcept;
[[nodiscard]] QSettings agent_settings();
void configure_vault_backend();
[[nodiscard]] bool sandboxed_build() noexcept;

}
