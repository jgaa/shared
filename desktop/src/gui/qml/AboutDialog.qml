import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    anchors.centerIn: parent
    modal: true
    focus: true
    title: "About shared"
    standardButtons: Dialog.Ok
    width: Math.min(parent ? parent.width - 80 : 520, 520)
    height: Math.min(parent ? parent.height - 80 : implicitHeight, 520)
    padding: 16

    contentItem: ScrollView {
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        contentWidth: availableWidth

        Column {
            width: parent.availableWidth
            spacing: 16

            Label {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "shared is a server-less peer-to-peer application for transferring clipboard text and files between untrusted devices."
            }

            GridLayout {
                width: parent.width
                columns: 2
                columnSpacing: 16
                rowSpacing: 8

                Label { text: "App version" }
                Label { text: app_controller.application_version }

                Label { text: "Qt version" }
                Label { text: app_controller.qt_version }

                Label { text: "Build ABI" }
                Label { text: app_controller.build_abi }

                Label { text: "Build time" }
                Label { text: app_controller.build_timestamp }
            }

            Label {
                width: parent.width
                wrapMode: Text.WordWrap
                textFormat: Text.RichText
                text: 'On GitHub: <a href="https://github.com/jgaa/shared">https://github.com/jgaa/shared</a>'
                onLinkActivated: function(link) { Qt.openUrlExternally(link) }
            }
        }
    }
}
