#include "tray_controller.h"

#include "app_controller.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QPoint>
#include <QtCore/QRect>
#include <QtCore/QSettings>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtGui/QAction>
#include <QtGui/QCloseEvent>
#include <QtGui/QGuiApplication>
#include <QtGui/QPainter>
#include <QtGui/QScreen>
#include <QtGui/QWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QSystemTrayIcon>

#include <algorithm>
#include <limits>

namespace shared::desktop::gui {

namespace {

constexpr auto shared_icon_path = ":/shared/icons/shared-icon.svg";
constexpr auto settings_group = "window";
constexpr auto x_key = "x";
constexpr auto y_key = "y";
constexpr auto width_key = "width";
constexpr auto height_key = "height";
constexpr auto maximized_key = "maximized";

bool running_on_wayland()
{
    return QGuiApplication::platformName().contains(QStringLiteral("wayland"), Qt::CaseInsensitive);
}

int squared_distance_to_rect(const QPoint &point, const QRect &rect)
{
    const auto dx = point.x() < rect.left()
        ? rect.left() - point.x()
        : (point.x() > rect.right() ? point.x() - rect.right() : 0);
    const auto dy = point.y() < rect.top()
        ? rect.top() - point.y()
        : (point.y() > rect.bottom() ? point.y() - rect.bottom() : 0);
    return dx * dx + dy * dy;
}

QRect clamp_window_geometry(const QRect &geometry)
{
    const auto screens = QGuiApplication::screens();
    if (screens.isEmpty()) {
        return geometry;
    }

    QRect target = geometry;
    QScreen *best_screen = nullptr;
    auto best_intersection_area = -1;

    for (auto *screen : screens) {
        if (screen == nullptr) {
            continue;
        }

        const auto available = screen->availableGeometry();
        const auto intersection = available.intersected(target);
        const auto intersection_area = intersection.width() * intersection.height();
        if (intersection_area > best_intersection_area) {
            best_intersection_area = intersection_area;
            best_screen = screen;
        }
    }

    if (best_screen == nullptr || best_intersection_area <= 0) {
        auto best_distance = std::numeric_limits<int>::max();
        const auto center = target.center();
        for (auto *screen : screens) {
            if (screen == nullptr) {
                continue;
            }

            const auto distance = squared_distance_to_rect(center, screen->availableGeometry());
            if (distance < best_distance) {
                best_distance = distance;
                best_screen = screen;
            }
        }
    }

    if (best_screen == nullptr) {
        best_screen = screens.constFirst();
    }

    const auto available = best_screen->availableGeometry();
    const auto width = std::clamp(target.width(), 320, available.width());
    const auto height = std::clamp(target.height(), 240, available.height());
    target.setSize({width, height});
    target.moveLeft(std::clamp(target.left(), available.left(), available.right() - width + 1));
    target.moveTop(std::clamp(target.top(), available.top(), available.bottom() - height + 1));
    return target;
}

QString format_alert_message(
    int pending_request_count,
    bool clipboard_approval_pending,
    bool file_approval_pending)
{
    QStringList parts{};
    if (pending_request_count > 0) {
        parts.append(pending_request_count == 1
            ? QStringLiteral("1 peer enrollment approval")
            : QStringLiteral("%1 peer enrollment approvals").arg(pending_request_count));
    }
    if (clipboard_approval_pending) {
        parts.append(QStringLiteral("clipboard approval"));
    }
    if (file_approval_pending) {
        parts.append(QStringLiteral("file approval"));
    }
    return parts.join(QStringLiteral(", "));
}

}

tray_controller::tray_controller(app_controller *controller, QWindow *window, QObject *parent)
    : QObject{parent}
    , controller_{controller}
    , window_{window}
{
    if (controller_ == nullptr || window_ == nullptr) {
        return;
    }

    restore_window_placement();

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        window_->installEventFilter(this);
        show_window();
        return;
    }

    normal_icon_ = QIcon(QLatin1StringView{shared_icon_path});
    alert_icon_ = build_alert_icon();

    tray_icon_ = new QSystemTrayIcon{normal_icon_, this};
    tray_icon_->setToolTip(QStringLiteral("Shared"));

    menu_ = new QMenu{};
    toggle_visibility_action_ = menu_->addAction(QStringLiteral("Hide Shared"));
    quit_action_ = menu_->addAction(QStringLiteral("Quit"));
    tray_icon_->setContextMenu(menu_);

    animation_timer_ = new QTimer{this};
    animation_timer_->setInterval(600);

    connect(toggle_visibility_action_, &QAction::triggered, this, &tray_controller::toggle_window_visibility);
    connect(quit_action_, &QAction::triggered, this, &tray_controller::request_quit);
    connect(animation_timer_, &QTimer::timeout, this, &tray_controller::update_icon);
    connect(tray_icon_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
            toggle_window_visibility();
        }
    });
    connect(controller_, &app_controller::state_changed, this, &tray_controller::refresh_state);
    connect(controller_, &app_controller::clipboard_approval_changed, this, &tray_controller::refresh_state);
    connect(controller_, &app_controller::file_approval_changed, this, &tray_controller::refresh_state);
    connect(window_, &QWindow::visibilityChanged, this, [this]() {
        if (toggle_visibility_action_ == nullptr || window_ == nullptr) {
            return;
        }
        toggle_visibility_action_->setText(window_->isVisible()
            ? QStringLiteral("Hide Shared")
            : QStringLiteral("Show Shared"));
    });

    window_->installEventFilter(this);
    tray_icon_->show();
    refresh_state();
    show_window();
}

tray_controller::~tray_controller()
{
    if (window_ != nullptr) {
        window_->removeEventFilter(this);
    }
    if (tray_icon_ != nullptr) {
        tray_icon_->setContextMenu(nullptr);
    }
    delete menu_;
}

bool tray_controller::available() const
{
    return tray_icon_ != nullptr;
}

bool tray_controller::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == window_ && event != nullptr && event->type() == QEvent::Hide) {
        save_window_placement();
    }

    if (watched == window_
        && event != nullptr
        && event->type() == QEvent::Close
        && !allow_window_close_) {
        save_window_placement();

        if (tray_icon_ == nullptr) {
            return QObject::eventFilter(watched, event);
        }

        auto *close_event = static_cast<QCloseEvent *>(event);
        close_event->ignore();
        hide_window();
        if (QSystemTrayIcon::supportsMessages()) {
            tray_icon_->showMessage(
                QStringLiteral("Shared"),
                QStringLiteral("Shared is still running in the system tray."),
                QSystemTrayIcon::Information,
                3000);
        }
        return true;
    }

    return QObject::eventFilter(watched, event);
}

void tray_controller::toggle_window_visibility()
{
    if (window_ == nullptr) {
        return;
    }

    if (window_->isVisible()) {
        hide_window();
        return;
    }

    show_window();
}

void tray_controller::show_window()
{
    if (window_ == nullptr) {
        return;
    }

    restore_window_placement();
    if (restore_maximized_on_show_) {
        window_->showMaximized();
    } else {
        window_->show();
    }
    window_->raise();
    window_->requestActivate();
}

void tray_controller::hide_window()
{
    if (window_ == nullptr) {
        return;
    }

    save_window_placement();
    window_->hide();
}

void tray_controller::request_quit()
{
    allow_window_close_ = true;
    save_window_placement();
    QCoreApplication::quit();
}

void tray_controller::refresh_state()
{
    if (controller_ == nullptr || tray_icon_ == nullptr) {
        return;
    }

    const auto pending_request_count = controller_->pending_requests().size();
    const auto clipboard_approval_pending = controller_->clipboard_approval_pending();
    const auto file_approval_pending = controller_->file_approval_pending();

    notify_new_alerts(
        pending_request_count,
        clipboard_approval_pending,
        file_approval_pending);

    alert_active_ =
        pending_request_count > 0 || clipboard_approval_pending || file_approval_pending;

    if (alert_active_) {
        if (!animation_timer_->isActive()) {
            animation_phase_alert_ = true;
            animation_timer_->start();
        }
    } else {
        animation_timer_->stop();
        animation_phase_alert_ = false;
    }

    update_tool_tip();
    update_icon();

    last_pending_request_count_ = pending_request_count;
    last_clipboard_approval_pending_ = clipboard_approval_pending;
    last_file_approval_pending_ = file_approval_pending;
}

void tray_controller::update_tool_tip()
{
    if (controller_ == nullptr || tray_icon_ == nullptr) {
        return;
    }

    const auto pending_request_count = controller_->pending_requests().size();
    const auto clipboard_approval_pending = controller_->clipboard_approval_pending();
    const auto file_approval_pending = controller_->file_approval_pending();

    QString tool_tip{QStringLiteral("Shared")};
    if (pending_request_count > 0 || clipboard_approval_pending || file_approval_pending) {
        tool_tip += QStringLiteral("\nPending: ")
            + format_alert_message(
                pending_request_count,
                clipboard_approval_pending,
                file_approval_pending);
    } else {
        tool_tip += QStringLiteral("\nNo pending approvals");
    }

    tray_icon_->setToolTip(tool_tip);
}

void tray_controller::update_icon()
{
    if (tray_icon_ == nullptr) {
        return;
    }

    if (!alert_active_) {
        tray_icon_->setIcon(normal_icon_);
        return;
    }

    tray_icon_->setIcon(animation_phase_alert_ ? alert_icon_ : normal_icon_);
    animation_phase_alert_ = !animation_phase_alert_;
}

void tray_controller::notify_new_alerts(
    int pending_request_count,
    bool clipboard_approval_pending,
    bool file_approval_pending)
{
    if (tray_icon_ == nullptr || !QSystemTrayIcon::supportsMessages()) {
        return;
    }

    if (pending_request_count > last_pending_request_count_) {
        tray_icon_->showMessage(
            QStringLiteral("Shared"),
            pending_request_count == 1
                ? QStringLiteral("A peer enrollment is waiting for approval.")
                : QStringLiteral("%1 peer enrollments are waiting for approval.").arg(pending_request_count),
            QSystemTrayIcon::Warning,
            5000);
    }

    if (clipboard_approval_pending && !last_clipboard_approval_pending_) {
        tray_icon_->showMessage(
            QStringLiteral("Shared"),
            QStringLiteral("Incoming clipboard transfer requires approval from %1.")
                .arg(controller_->clipboard_approval_sender_name()),
            QSystemTrayIcon::Warning,
            5000);
    }

    if (file_approval_pending && !last_file_approval_pending_) {
        tray_icon_->showMessage(
            QStringLiteral("Shared"),
            QStringLiteral("Incoming file %1 requires approval from %2.")
                .arg(controller_->file_approval_filename(), controller_->file_approval_sender_name()),
            QSystemTrayIcon::Warning,
            5000);
    }
}

QIcon tray_controller::build_alert_icon() const
{
    QIcon icon{};
    for (const auto size : {16, 22, 24, 32, 48, 64}) {
        QPixmap pixmap = normal_icon_.pixmap(size, size);
        if (pixmap.isNull()) {
            continue;
        }

        QPainter painter{&pixmap};
        painter.setRenderHint(QPainter::Antialiasing, true);

        const auto badge_diameter = std::max(8, size / 2);
        const QRect badge_rect{
            size - badge_diameter,
            0,
            badge_diameter,
            badge_diameter,
        };

        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor{0xcc, 0x2f, 0x1d});
        painter.drawEllipse(badge_rect);

        QFont font = QGuiApplication::font();
        font.setBold(true);
        font.setPixelSize(std::max(7, badge_diameter - 4));
        painter.setFont(font);
        painter.setPen(Qt::white);
        painter.drawText(badge_rect, Qt::AlignCenter, QStringLiteral("!"));

        painter.end();
        icon.addPixmap(pixmap);
    }

    return icon.isNull() ? normal_icon_ : icon;
}

void tray_controller::restore_window_placement()
{
    if (window_ == nullptr) {
        return;
    }

    QSettings settings{};
    settings.beginGroup(QString::fromLatin1(settings_group));
    const auto has_geometry =
        settings.contains(QString::fromLatin1(x_key))
        && settings.contains(QString::fromLatin1(y_key))
        && settings.contains(QString::fromLatin1(width_key))
        && settings.contains(QString::fromLatin1(height_key));
    if (!has_geometry) {
        settings.endGroup();
        return;
    }

    const QRect saved_geometry{
        settings.value(QString::fromLatin1(x_key)).toInt(),
        settings.value(QString::fromLatin1(y_key)).toInt(),
        settings.value(QString::fromLatin1(width_key)).toInt(),
        settings.value(QString::fromLatin1(height_key)).toInt(),
    };
    restore_maximized_on_show_ = settings.value(QString::fromLatin1(maximized_key), false).toBool();
    settings.endGroup();

    if (running_on_wayland()) {
        const auto size = saved_geometry.size();
        if (size.width() > 0 && size.height() > 0) {
            window_->resize(size);
        }
        return;
    }

    const auto clamped_geometry = clamp_window_geometry(saved_geometry);
    window_->setGeometry(clamped_geometry);
}

void tray_controller::save_window_placement() const
{
    if (window_ == nullptr) {
        return;
    }

    const auto geometry = clamp_window_geometry(window_->geometry());
    QSettings settings{};
    settings.beginGroup(QString::fromLatin1(settings_group));
    settings.setValue(QString::fromLatin1(x_key), geometry.x());
    settings.setValue(QString::fromLatin1(y_key), geometry.y());
    settings.setValue(QString::fromLatin1(width_key), geometry.width());
    settings.setValue(QString::fromLatin1(height_key), geometry.height());
    settings.setValue(QString::fromLatin1(maximized_key), window_->visibility() == QWindow::Maximized);
    settings.endGroup();
    settings.sync();
}

}
