#pragma once

#include <QtCore/QString>

namespace shared::desktop::core {

struct app_metadata {
    static const inline QString organization_name{QStringLiteral("shared")};
    static const inline QString organization_domain{QStringLiteral("shared.local")};
    static const inline QString daemon_application_name{QStringLiteral("shared-daemon")};
    static const inline QString gui_application_name{QStringLiteral("shared-gui")};
    static const inline QString settings_group_limits{QStringLiteral("limits")};
    static const inline QString settings_key_clipboard_limit_bytes{QStringLiteral("clipboard_limit_bytes")};
};

}
