import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    property var controller
    property string selectedPeerId: ""

    title: "Send Clipboard"
    modal: true
    width: Math.min(parent.width - 80, 420)
    height: Math.min(parent ? parent.height - 80 : 420, 420)
    padding: 16
    standardButtons: Dialog.Close

    onOpened: selectedPeerId = ""

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        Label {
            text: "Choose one verified peer to receive the current clipboard text."
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
                width: parent.width
                spacing: 8

                Repeater {
                    model: root.controller ? root.controller.verified_peers : []

                    delegate: RadioButton {
                        required property var modelData

                        text: modelData.name + (modelData.address.length > 0 ? " (" + modelData.address + ")" : "")
                        checked: root.selectedPeerId === modelData.peer_id
                        enabled: modelData.status_label !== "Unavailable"
                        onClicked: root.selectedPeerId = modelData.peer_id
                    }
                }

                Label {
                    visible: (root.controller ? root.controller.verified_peers.length : 0) === 0
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
                enabled: root.selectedPeerId.length > 0
                onClicked: {
                    if (root.controller && root.controller.send_clipboard_to_peer(root.selectedPeerId)) {
                        root.close()
                    }
                }
            }
        }
    }
}
