import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var app_controller

    property string pendingRemovalPeerId: ""
    property string pendingRemovalPeerName: ""

    anchors.centerIn: parent
    modal: true
    focus: true
    title: "Verified Peers"
    standardButtons: Dialog.Close
    width: Math.min(parent ? parent.width - 80 : 880, 880)
    height: Math.min(parent ? parent.height - 80 : 620, 620)
    padding: 16

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Verified peers from the signed peer list. Status updates live while the daemon is running."
            wrapMode: Text.WordWrap
            color: palette.mid
            Layout.fillWidth: true
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: "#f7f4ec"
            border.color: "#d2c7b6"

            ListView {
                id: verified_peers_list
                anchors.fill: parent
                anchors.margins: 10
                clip: true
                spacing: 8
                model: app_controller.verified_peers

                delegate: Frame {
                    width: ListView.view.width

                    RowLayout {
                        anchors.fill: parent
                        spacing: 12

                        Rectangle {
                            Layout.alignment: Qt.AlignTop
                            width: 14
                            height: 14
                            radius: 7
                            color: status_color
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4

                            Label {
                                text: name
                                font.bold: true
                                Layout.fillWidth: true
                            }

                            Label {
                                text: peer_id
                                color: palette.mid
                                wrapMode: Text.WrapAnywhere
                                Layout.fillWidth: true
                            }

                            Label {
                                visible: address.length > 0 && address !== last_known_address
                                text: address
                                Layout.fillWidth: true
                            }

                            Label {
                                visible: last_known_address.length > 0
                                text: "Last known IP: " + last_known_address
                                color: palette.mid
                                wrapMode: Text.WrapAnywhere
                                Layout.fillWidth: true
                            }
                        }

                        ColumnLayout {
                            Layout.alignment: Qt.AlignTop
                            spacing: 4

                            Label {
                                text: status_label
                                color: status_color
                                font.bold: true
                            }

                            Label {
                                text: "Last: " + last_communicated
                                color: palette.mid
                            }

                            ToolButton {
                                visible: app_controller.trusted_agent
                                text: "Delete"
                                icon.name: "edit-delete"
                                onClicked: {
                                    root.pendingRemovalPeerId = peer_id
                                    root.pendingRemovalPeerName = name
                                    confirm_remove_dialog.open()
                                }
                            }
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: app_controller.verified_peer_count === 0
                text: "No verified peers are available yet."
                color: palette.mid
            }
        }
    }

    Dialog {
        id: confirm_remove_dialog

        anchors.centerIn: parent
        modal: true
        title: "Remove Authorized Peer"
        standardButtons: Dialog.Yes | Dialog.No

        onAccepted: {
            if (root.pendingRemovalPeerId.length > 0) {
                app_controller.remove_authorized_peer(root.pendingRemovalPeerId)
            }
            root.pendingRemovalPeerId = ""
            root.pendingRemovalPeerName = ""
        }

        onRejected: {
            root.pendingRemovalPeerId = ""
            root.pendingRemovalPeerName = ""
        }

        contentItem: Label {
            width: 360
            wrapMode: Text.WordWrap
            text: root.pendingRemovalPeerName.length > 0
                ? "Remove " + root.pendingRemovalPeerName + " from the list of authorized agents? Existing connections to that peer will be dropped."
                : "Remove this peer from the list of authorized agents? Existing connections to that peer will be dropped."
        }
    }
}
