#pragma once

#include <QtCore/QSettings>
#include <QtCore/QString>

namespace shared::desktop::core {

class settings_repository {
public:
    static constexpr int default_clipboard_limit_bytes{1024 * 1024};
    static constexpr int maximum_clipboard_limit_bytes{8 * 1024 * 1024};

    settings_repository();

    [[nodiscard]] bool local_socket_enabled() const;
    void set_local_socket_enabled(bool value);
    [[nodiscard]] int clipboard_limit_bytes() const;
    void set_clipboard_limit_bytes(int value);
    [[nodiscard]] bool auto_accept_clipboard() const;
    void set_auto_accept_clipboard(bool value);
    [[nodiscard]] bool auto_accept_files() const;
    void set_auto_accept_files(bool value);
    [[nodiscard]] QString download_path() const;
    void set_download_path(const QString &value);

private:
    [[nodiscard]] QSettings create_settings() const;
};

}
