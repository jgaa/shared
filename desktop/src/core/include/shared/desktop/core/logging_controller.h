#pragma once

#include "shared/desktop/core/logging.h"

#include <QtCore/QString>

#include <optional>

class QSettings;

namespace shared::desktop::core {

class logging_controller {
public:
    static constexpr int disabled_level{0};
    static constexpr int error_level{1};
    static constexpr int warn_level{2};
    static constexpr int notice_level{3};
    static constexpr int info_level{4};
    static constexpr int debug_level{5};
    static constexpr int trace_level{6};

    struct runtime_options {
        QString default_log_file_path{};
        std::optional<int> console_level_override{};
        std::optional<int> file_level_override{};
        QString log_file_override{};
        bool has_log_file_override{};
        bool truncate_log_file_override{};
        bool enable_ring_buffer{};
    };

    void initialize(const runtime_options &options) const;
    void ensure_defaults(QSettings &settings, const QString &default_log_file_path) const;
    [[nodiscard]] QString settings_file_path() const;

    [[nodiscard]] static int default_log_level() noexcept;
    [[nodiscard]] static QString default_log_file_path(const QString &application_name);
    [[nodiscard]] static std::optional<int> parse_log_level_name(const QString &name) noexcept;
    [[nodiscard]] static QString normalize_path(const QString &path);
    [[nodiscard]] static QStringList log_level_labels();

private:
    static void install_qt_message_handler();
};

}
