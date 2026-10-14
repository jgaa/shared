#pragma once

#include <QtCore/QString>
#include <QtCore/QStringList>

namespace shared::desktop::gui::desktop_integration {

// Registration is checked separately from the user's saved preference.
[[nodiscard]] bool autostart_registered();
[[nodiscard]] bool set_autostart_enabled(bool enabled, QString &error_message);
[[nodiscard]] QStringList select_files(const QString &initial_directory, QString &error_message);

}
