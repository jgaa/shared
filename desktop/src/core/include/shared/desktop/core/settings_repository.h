#pragma once

#include <QtCore/QSettings>

namespace shared::desktop::core {

class settings_repository {
public:
    static constexpr int default_clipboard_limit_bytes{1024 * 1024};
    static constexpr int maximum_clipboard_limit_bytes{8 * 1024 * 1024};

    settings_repository();

    [[nodiscard]] int clipboard_limit_bytes() const;
    void set_clipboard_limit_bytes(int value);

private:
    [[nodiscard]] QSettings create_settings() const;
};

}
