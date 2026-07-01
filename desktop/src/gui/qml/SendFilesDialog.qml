import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    property var controller
    property string selectedPeerId: ""
    property var selectedFiles: []

    title: "Send Files"
    modal: true
    width: Math.min(parent ? parent.width - 80 : 640, 640)
    height: Math.min(parent ? parent.height - 80 : 520, 520)
    padding: 16
    standardButtons: Dialog.Close

    onOpened: selectedPeerId = ""

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        Label {
            text: "Choose one verified peer to receive the selected files."
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        Frame {
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(selected_files_column.implicitHeight + 24, 120)

            ScrollView {
                anchors.fill: parent
                clip: true

                ColumnLayout {
                    id: selected_files_column

                    width: parent.width
                    spacing: 6

                    Repeater {
                        model: root.selectedFiles

                        delegate: Label {
                            required property var modelData

                            text: modelData
                            wrapMode: Text.WrapAnywhere
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
                width: parent.width
                spacing: 8

                Repeater {
                    model: root.controller ? root.controller.verified_peers : null

                    delegate: RadioButton {
                        text: name + (address.length > 0 ? " (" + address + ")" : "")
                        checked: root.selectedPeerId === peer_id
                        enabled: status_label !== "Unavailable"
                        onClicked: root.selectedPeerId = peer_id
                    }
                }

                Label {
                    visible: (root.controller ? root.controller.verified_peer_count : 0) === 0
                    text: "No verified peers are available yet."
                    color: palette.mid
                    Layout.fillWidth: true
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true

            Item {
                Layout.fillWidth: true
            }

            Button {
                text: "Send"
                enabled: root.selectedPeerId.length > 0 && root.selectedFiles.length > 0
                onClicked: {
                    if (root.controller && root.controller.send_files_to_peer(root.selectedPeerId, root.selectedFiles)) {
                        root.close()
                    }
                }
            }
        }
    }
}
