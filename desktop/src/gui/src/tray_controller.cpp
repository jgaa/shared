#include "tray_controller.h"

#include "app_controller.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtGui/QAction>
#include <QtGui/QCloseEvent>
#include <QtGui/QGuiApplication>
#include <QtGui/QPainter>
#include <QtGui/QWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QSystemTrayIcon>

#include <algorithm>

namespace shared::desktop::gui {

namespace {

constexpr auto shared_icon_path = ":/shared/icons/shared-icon.svg";

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
    if (controller_ == nullptr || window_ == nullptr || !QSystemTrayIcon::isSystemTrayAvailable()) {
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
    if (watched == window_
        && event != nullptr
        && event->type() == QEvent::Close
        && tray_icon_ != nullptr
        && !allow_window_close_) {
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

    window_->show();
    window_->raise();
    window_->requestActivate();
}

void tray_controller::hide_window()
{
    if (window_ == nullptr) {
        return;
    }

    window_->hide();
}

void tray_controller::request_quit()
{
    allow_window_close_ = true;
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

}
