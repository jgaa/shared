import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var app_controller

    property string currentPane: "local"
    property bool showEnrollmentSettings: !app_controller.configured || app_controller.trusted_agent
    readonly property bool trustedAgentPaneAvailable: !app_controller.trusted_agent
    readonly property int stackIndex: {
        if (currentPane === "local") {
            return 0
        }
        if (currentPane === "trusted" && trustedAgentPaneAvailable) {
            return 1
        }
        return trustedAgentPaneAvailable ? 2 : 1
    }

    function reload() {
        if (!trustedAgentPaneAvailable && currentPane === "trusted") {
            currentPane = "local"
        }

        local_enrollment_host.text = app_controller.local_enrollment_host
        local_enrollment_port.value = app_controller.local_enrollment_port
        local_peer_host.text = app_controller.local_peer_host
        local_peer_port.value = app_controller.local_peer_port
        trusted_agent_host.text = app_controller.trusted_agent_host
        trusted_agent_port.value = app_controller.trusted_agent_port
        trusted_agent_peer_port.value = app_controller.trusted_agent_peer_port
        local_socket_enabled.checked = app_controller.local_socket_enabled
        start_automatically.checked = app_controller.start_automatically
        clipboard_limit.value = app_controller.clipboard_limit_megabytes
        auto_accept_clipboard.checked = app_controller.auto_accept_clipboard
        auto_accept_files.checked = app_controller.auto_accept_files
        download_path.text = app_controller.download_path
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
                highlighted: root.currentPane === "local"
                onClicked: root.currentPane = "local"
            }

            Button {
                visible: root.trustedAgentPaneAvailable
                text: "Trusted Agent"
                highlighted: root.currentPane === "trusted"
                onClicked: root.currentPane = "trusted"
            }

            Button {
                text: "Log"
                highlighted: root.currentPane === "log"
                onClicked: root.currentPane = "log"
            }

            Item {
                Layout.fillWidth: true
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: root.stackIndex

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

                            Label {
                                visible: root.showEnrollmentSettings
                                text: "Enrollment Listen IP"
                            }
                            TextField {
                                id: local_enrollment_host
                                visible: root.showEnrollmentSettings
                                Layout.fillWidth: true
                                placeholderText: "0.0.0.0"
                                onEditingFinished: app_controller.local_enrollment_host = text
                            }

                            Label {
                                visible: root.showEnrollmentSettings
                                text: "Enrollment TCP Port"
                            }
                            SpinBox {
                                id: local_enrollment_port
                                visible: root.showEnrollmentSettings
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

                            Label { text: "Enable local socket" }
                            CheckBox {
                                id: local_socket_enabled
                                onToggled: app_controller.local_socket_enabled = checked
                            }

                            Label { text: "Start automatically" }
                            CheckBox {
                                id: start_automatically
                                onToggled: app_controller.start_automatically = checked
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

                            Label { text: "Auto-accept clipboard" }
                            CheckBox {
                                id: auto_accept_clipboard
                                onToggled: app_controller.auto_accept_clipboard = checked
                            }

                            Label { text: "Auto-accept files" }
                            CheckBox {
                                id: auto_accept_files
                                onToggled: app_controller.auto_accept_files = checked
                            }

                            Label { text: "Download to" }
                            TextField {
                                id: download_path
                                Layout.fillWidth: true
                                placeholderText: "Downloads"
                                onEditingFinished: app_controller.download_path = text
                            }
                        }
                    }
                }
            }

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
                        app_controller: root.app_controller
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

    Connections {
        target: app_controller

        function onTransferSettingsChanged() {
            root.reload()
        }
    }
}
