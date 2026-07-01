#pragma once

#include "shared/desktop/core/logging.h"

#include <QtCore/QString>
#include <QtCore/QStringList>

#include <deque>
#include <mutex>

namespace shared::desktop::core {

struct captured_log_line {
    QString level{};
    QString line{};
};

class log_ring_buffer final {
public:
    static log_ring_buffer &instance() noexcept;

    void append(const logfault::Message &message) noexcept;
    [[nodiscard]] QStringList snapshot_lines() const;

private:
    static constexpr std::size_t capacity_{500};
    static constexpr qsizetype max_line_length_{2048};

    mutable std::mutex mutex_{};
    std::deque<captured_log_line> lines_{};
};

class ring_buffer_handler final : public logfault::Handler {
public:
    explicit ring_buffer_handler(logfault::LogLevel level)
        : Handler(level)
    {
    }

    void LogMessage(const logfault::Message &message) LOGFAULT_NOEXCEPT override;
};

}
