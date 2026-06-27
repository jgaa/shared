import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var app_controller

    anchors.centerIn: parent
    modal: true
    focus: true
    title: qsTr("About Shared")
    standardButtons: Dialog.Ok
    width: Math.min(parent ? parent.width - 80 : 520, 520)
    height: Math.min(parent ? parent.height - 80 : 520, 520)
    padding: 16

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        ScrollView {
            id: details_view

            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            Column {
                width: details_view.availableWidth
                spacing: 16

                Label {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: qsTr("Shared is a server-less peer-to-peer application for securely transferring clipboard text and files between devices without relying on a central service.")
                }

                GridLayout {
                    width: parent.width
                    columns: 2
                    columnSpacing: 16
                    rowSpacing: 8

                    Label { text: "App version" }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WrapAnywhere
                        text: app_controller.application_version
                    }

                    Label { text: "Qt version" }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WrapAnywhere
                        text: app_controller.qt_version
                    }

                    Label { text: qsTr("OpenSSL library") }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WrapAnywhere
                        text: app_controller.openssl_library_version
                    }

                    Label { text: qsTr("License") }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WrapAnywhere
                        text: qsTr("GPL 3")
                    }
                }

                Label {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    textFormat: Text.RichText
                    text: qsTr('Developed by <a href="https://lastviking.eu/">The Last Viking LTD</a>')
                    onLinkActivated: function(link) { Qt.openUrlExternally(link) }
                }

                Label {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: qsTr("Shared is intended for users working across multiple hosts, VMs, and trust boundaries where clipboard and file exchange should stay local and encrypted.")
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
}
