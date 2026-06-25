#pragma once

#include <QtCore/QString>

namespace shared::desktop::core {

struct app_metadata {
    static const inline QString organization_name{QStringLiteral("The Last Viking LTD")};
    static const inline QString organization_domain{QStringLiteral("lastviking.eu")};
    static const inline QString application_display_name{QStringLiteral("Shared")};
    static const inline QString daemon_application_name{QStringLiteral("shared-daemon")};
    static const inline QString gui_application_name{QStringLiteral("shared")};
    static const inline QString settings_group_limits{QStringLiteral("limits")};
    static const inline QString settings_group_transfers{QStringLiteral("transfers")};
    static const inline QString settings_key_clipboard_limit_bytes{QStringLiteral("clipboard_limit_bytes")};
    static const inline QString settings_key_auto_accept_clipboard{QStringLiteral("auto_accept_clipboard")};
    static const inline QString settings_key_auto_accept_files{QStringLiteral("auto_accept_files")};
    static const inline QString settings_key_download_path{QStringLiteral("download_path")};
};

}
