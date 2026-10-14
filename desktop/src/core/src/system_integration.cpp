#include "shared/desktop/core/system_integration.h"
#include "shared/desktop/core/app_metadata.h"

#include <safekeeping/SafeKeeping.h>

namespace shared::desktop::core::system_integration {

shared::v1::PlatformGadget::Platform current_platform() noexcept
{
    using platform = shared::v1::PlatformGadget::Platform;
#if defined(Q_OS_MACOS)
    return platform::PLATFORM_MACOS;
#elif defined(Q_OS_WIN)
    return platform::PLATFORM_WINDOWS;
#elif defined(Q_OS_ANDROID)
    return platform::PLATFORM_ANDROID;
#elif defined(Q_OS_LINUX)
    return platform::PLATFORM_LINUX;
#else
    return platform::PLATFORM_UNSPECIFIED;
#endif
}

QSettings agent_settings()
{
    // Keep the agent store independent of the GUI/headless application name.
    // Respect Qt's default format so tests can use an isolated INI store.
    return QSettings{QSettings::defaultFormat(), QSettings::UserScope,
        app_metadata::organization_name, app_metadata::organization_name};
}

bool sandboxed_build() noexcept
{
#if SHARED_FLATPAK_BUILD
    return true;
#else
    return false;
#endif
}

void configure_vault_backend()
{
#if defined(Q_OS_LINUX)
    using vault = jgaa::safekeeping::SafeKeeping;
    vault::setLinuxVaultRootName("eu.lastviking.shared");
    vault::setLinuxVaultBackend(vault::LinuxVaultBackend::Auto);
#endif
    // SafeKeeping selects the native backend (including Keychain) elsewhere.
}

}
