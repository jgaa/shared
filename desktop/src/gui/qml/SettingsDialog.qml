import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    property int currentPane: 0

    function reload() {
        if (app_controller.trusted_agent && currentPane === 1) {
            currentPane = 0
        }

        local_enrollment_host.text = app_controller.local_enrollment_host
        local_enrollment_port.value = app_controller.local_enrollment_port
        local_peer_host.text = app_controller.local_peer_host
        local_peer_port.value = app_controller.local_peer_port
        trusted_agent_host.text = app_controller.trusted_agent_host
        trusted_agent_port.value = app_controller.trusted_agent_port
        trusted_agent_peer_port.value = app_controller.trusted_agent_peer_port
        clipboard_limit.value = app_controller.clipboard_limit_megabytes
        log_settings.reload()
    }

    x: (parent.width - width) / 2
    y: (parent.height - height) / 2
    width: Math.min(parent.width - 80, 760)
    height: Math.min(parent.height - 80, 560)
    modal: true
    title: "Settings"
    onOpened: reload()

    ColumnLayout {
        anchors.fill: parent
        spacing: 16

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Button {
                text: "Local"
                highlighted: root.currentPane === 0
                onClicked: root.currentPane = 0
            }

            Button {
                visible: !app_controller.trusted_agent
                text: "Trusted Agent"
                highlighted: root.currentPane === 1
                onClicked: root.currentPane = 1
            }

            Button {
                text: "Log"
                highlighted: root.currentPane === 2
                onClicked: root.currentPane = 2
            }

            Item {
                Layout.fillWidth: true
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: root.currentPane

            ScrollView {
                clip: true

                ColumnLayout {
                    width: parent.width
                    spacing: 20

                    Frame {
                        Layout.fillWidth: true

                        GridLayout {
                            anchors.fill: parent
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: 10

                            Label { text: "Enrollment Listen IP" }
                            TextField {
                                id: local_enrollment_host
                                Layout.fillWidth: true
                                placeholderText: "0.0.0.0"
                                onEditingFinished: app_controller.local_enrollment_host = text
                            }

                            Label { text: "Enrollment TCP Port" }
                            SpinBox {
                                id: local_enrollment_port
                                from: 1
                                to: 65535
                                editable: true
                                onValueModified: app_controller.local_enrollment_port = value
                            }

                            Label { text: "Peer Listen IP" }
                            TextField {
                                id: local_peer_host
                                Layout.fillWidth: true
                                placeholderText: "0.0.0.0"
                                onEditingFinished: app_controller.local_peer_host = text
                            }

                            Label { text: "Peer TCP Port" }
                            SpinBox {
                                id: local_peer_port
                                from: 1
                                to: 65535
                                editable: true
                                onValueModified: app_controller.local_peer_port = value
                            }
                        }
                    }

                    Frame {
                        Layout.fillWidth: true

                        GridLayout {
                            anchors.fill: parent
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: 10

                            Label { text: "Clipboard Limit (MiB)" }
                            SpinBox {
                                id: clipboard_limit
                                from: 1
                                to: 8
                                editable: true
                                onValueModified: app_controller.clipboard_limit_megabytes = value
                            }
                        }
                    }
                }
            }

            ScrollView {
                visible: !app_controller.trusted_agent
                clip: true

                ColumnLayout {
                    width: parent.width
                    spacing: 20

                    Frame {
                        Layout.fillWidth: true

                        GridLayout {
                            anchors.fill: parent
                            columns: 2
                            columnSpacing: 16
                            rowSpacing: 10

                            Label { text: "Trusted Agent Host" }
                            TextField {
                                id: trusted_agent_host
                                Layout.fillWidth: true
                                placeholderText: "192.168.0.10"
                                onEditingFinished: app_controller.trusted_agent_host = text.trim()
                            }

                            Label { text: "Enrollment TCP Port" }
                            SpinBox {
                                id: trusted_agent_port
                                from: 1
                                to: 65535
                                editable: true
                                onValueModified: app_controller.trusted_agent_port = value
                            }

                            Label { text: "Peer TCP Port" }
                            SpinBox {
                                id: trusted_agent_peer_port
                                from: 1
                                to: 65535
                                editable: true
                                onValueModified: app_controller.trusted_agent_peer_port = value
                            }
                        }
                    }

                    Frame {
                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 8

                            Label {
                                text: "Pinned Enrollment Fingerprint"
                                font.bold: true
                            }

                            Label {
                                Layout.fillWidth: true
                                wrapMode: Text.WrapAnywhere
                                color: palette.mid
                                text: app_controller.trusted_agent_fingerprint.length > 0
                                    ? app_controller.trusted_agent_fingerprint
                                    : "Not enrolled yet"
                            }
                        }
                    }
                }
            }

            Frame {
                Layout.fillWidth: true
                Layout.fillHeight: true

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 10

                    LogSettings {
                        id: log_settings
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                    }
                }
            }
        }

        DialogButtonBox {
            Layout.fillWidth: true
            standardButtons: DialogButtonBox.Close
            onRejected: root.close()
        }
    }
}
