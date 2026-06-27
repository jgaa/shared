import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ScrollView {
    id: root
    required property var app_controller

    anchors.fill: parent
    clip: true

    function reload() {
        app_level_box.currentIndex = app_controller.app_log_level
        file_level_box.currentIndex = app_controller.file_log_level
        log_path_field.text = app_controller.log_file_path
        prune_check.checked = app_controller.prune_log_file
    }

    GridLayout {
        id: form_layout

        width: root.availableWidth
        columns: width >= 460 ? 2 : 1
        rowSpacing: 10
        columnSpacing: 16

        Label {
            text: "Console Log Level"
        }

        ComboBox {
            id: app_level_box

            Layout.fillWidth: true
            model: app_controller.log_level_labels
            onActivated: app_controller.app_log_level = currentIndex
        }

        Label {
            text: "File Log Level"
        }

        ComboBox {
            id: file_level_box

            Layout.fillWidth: true
            model: app_controller.log_level_labels
            onActivated: app_controller.file_log_level = currentIndex
        }

        Label {
            text: "Log File Path"
        }

        TextField {
            id: log_path_field

            Layout.fillWidth: true
            placeholderText: "/tmp/shared-gui.log"
            onEditingFinished: app_controller.log_file_path = text.trim()
        }

        Item {
        }

        CheckBox {
            id: prune_check

            text: "Truncate log file on startup"
            onToggled: app_controller.prune_log_file = checked
        }

        Label {
            Layout.columnSpan: form_layout.columns
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: palette.mid
            text: "Logging settings apply on the next application start. Command-line options override them for the current run."
        }

        Label {
            Layout.columnSpan: form_layout.columns
            Layout.fillWidth: true
            wrapMode: Text.WrapAnywhere
            color: palette.mid
            text: "Settings file: " + app_controller.settings_file_path
        }

        Item {
            Layout.fillHeight: true
        }
    }
}
