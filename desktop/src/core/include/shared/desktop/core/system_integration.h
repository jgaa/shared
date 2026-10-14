#pragma once

#include "shared.qpb.h"
#include <QtCore/QSettings>

namespace shared::desktop::core::system_integration {

[[nodiscard]] shared::v1::PlatformGadget::Platform current_platform() noexcept;
[[nodiscard]] QSettings agent_settings();
void configure_vault_backend();
// Call before constructing any QSslSocket, QSslCertificate, or QSslKey.
[[nodiscard]] bool configure_tls_backend(QString &error_message);
[[nodiscard]] bool sandboxed_build() noexcept;

}
