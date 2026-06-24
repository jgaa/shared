#include "shared/desktop/core/log_capture.h"

#include <QtCore/QLoggingCategory>

#include <sstream>

namespace shared::desktop::core {

Q_LOGGING_CATEGORY(shared_log_capture_log, "shared.desktop.core.log_capture")

log_ring_buffer &log_ring_buffer::instance() noexcept
{
    static log_ring_buffer instance{};
    return instance;
}

void log_ring_buffer::append(const logfault::Message &message) noexcept
{
    try {
        std::ostringstream out{};
        logfault::Handler::PrintMessage(out, message);

        captured_log_line line{
            .level = QString::fromLatin1(logfault::Handler::LevelName(message.level_)),
            .line = QString::fromStdString(out.str()),
        };

        std::lock_guard lock{mutex_};
        if (lines_.size() >= capacity_) {
            lines_.pop_front();
        }
        lines_.push_back(std::move(line));
    } catch (...) {
        qCWarning(shared_log_capture_log) << "Ignored exception while capturing a log line";
    }
}

QStringList log_ring_buffer::snapshot_lines() const
{
    std::lock_guard lock{mutex_};

    QStringList lines{};
    lines.reserve(static_cast<qsizetype>(lines_.size()));
    for (const auto &line : lines_) {
        lines.append(line.line);
    }

    return lines;
}

void ring_buffer_handler::LogMessage(const logfault::Message &message) LOGFAULT_NOEXCEPT
{
    log_ring_buffer::instance().append(message);
}

}
