#pragma once

#include <QtCore/QObject>
#include <QtGui/QIcon>

class QAction;
class QMenu;
class QSystemTrayIcon;
class QTimer;
class QWindow;

namespace shared::desktop::gui {

class app_controller;

class tray_controller final : public QObject {
    Q_OBJECT

public:
    tray_controller(app_controller *controller, QWindow *window, QObject *parent = nullptr);
    ~tray_controller() override;

    [[nodiscard]] bool available() const;

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void restore_window_placement();
    void save_window_placement() const;
    void toggle_window_visibility();
    void show_window();
    void hide_window();
    void request_quit();
    void refresh_state();
    void update_tool_tip();
    void update_icon();
    void notify_new_alerts(
        int pending_request_count,
        bool clipboard_approval_pending,
        bool file_approval_pending);
    [[nodiscard]] QIcon build_alert_icon() const;

    app_controller *controller_{};
    QWindow *window_{};
    QSystemTrayIcon *tray_icon_{};
    QMenu *menu_{};
    QAction *toggle_visibility_action_{};
    QAction *quit_action_{};
    QTimer *animation_timer_{};
    QIcon normal_icon_{};
    QIcon alert_icon_{};
    int last_pending_request_count_{};
    bool last_clipboard_approval_pending_{};
    bool last_file_approval_pending_{};
    bool alert_active_{};
    bool animation_phase_alert_{};
    bool allow_window_close_{};
    bool restore_maximized_on_show_{};
};

}
