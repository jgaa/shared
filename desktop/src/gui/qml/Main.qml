import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: window

    width: 900
    height: 600
    visible: true
    title: app_controller.app_name
    menuBar: MenuBar {
        Menu {
            title: "File"

            Action {
                text: "Peers"
                onTriggered: peers_dialog.open()
            }

            Action {
                text: "Log"
                onTriggered: log_viewer_dialog.open()
            }

            Action {
                text: "Settings"
                onTriggered: settings_dialog.open()
            }

            MenuSeparator {
            }

            Action {
                text: "Quit"
                onTriggered: Qt.quit()
            }
        }

        Menu {
            title: "Help"

            Action {
                text: "About"
                onTriggered: about_dialog.open()
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#f4efe4" }
            GradientStop { position: 1.0; color: "#d8e8f0" }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 32
        spacing: 24

        Frame {
            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 12

                Label {
                    text: app_controller.configured ? "Desktop shell" : "First-run setup"
                    font.pixelSize: 24
                    font.bold: true
                }

                Label {
                    text: app_controller.configured
                        ? app_controller.status_text
                        : "Choose whether this machine becomes the trusted agent or joins an existing one."
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }
        }

        Frame {
            visible: !app_controller.configured
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 16

                TabBar {
                    id: setup_tabs

                    Layout.fillWidth: true
                    currentIndex: 0

                    TabButton {
                        text: "Join Existing"
                    }

                    TabButton {
                        text: "Initialize Local"
                    }
                }

                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: setup_tabs.currentIndex

                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 16

                            Label {
                                text: "Join Existing Trusted Agent"
                                font.pixelSize: 20
                                font.bold: true
                            }

                            TextField {
                                id: peer_name

                                text: app_controller.default_agent_name
                                placeholderText: "Device name"
                                Layout.fillWidth: true
                            }

                            TextField {
                                id: peer_host

                                placeholderText: "Trusted agent host or IP"
                                Layout.fillWidth: true
                            }

                            RowLayout {
                                Layout.fillWidth: true

                                Label {
                                    text: "TCP Port"
                                }

                                SpinBox {
                                    id: peer_port

                                    from: 1
                                    to: 65535
                                    value: app_controller.trusted_agent_port
                                    editable: true
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true

                                TextField {
                                    id: peer_fingerprint

                                    placeholderText: "Enrollment fingerprint (abcd-1234)"
                                    Layout.fillWidth: true
                                }

                                Button {
                                    text: "Start Enrollment"
                                    onClicked: {
                                        const code = app_controller.prepare_join_trusted_agent(peer_name.text)
                                        if (!code || code.length === 0) {
                                            return
                                        }

                                        app_controller.complete_join_trusted_agent(
                                            peer_host.text,
                                            peer_port.value,
                                            peer_fingerprint.text)
                                    }
                                }
                            }

                            Item {
                                Layout.fillHeight: true
                            }
                        }
                    }

                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 16

                            Label {
                                text: "Initialize This Machine As Trusted Agent"
                                font.pixelSize: 20
                                font.bold: true
                            }

                            TextField {
                                id: trusted_name

                                text: app_controller.default_agent_name
                                placeholderText: "Device name"
                                Layout.fillWidth: true
                            }

                            RowLayout {
                                Layout.fillWidth: true

                                Label {
                                    text: "TCP Port"
                                }

                                SpinBox {
                                    id: trusted_port

                                    from: 1
                                    to: 65535
                                    value: app_controller.local_enrollment_port
                                    editable: true
                                }
                            }

                            Item {
                                Layout.fillHeight: true
                            }

                            Button {
                                text: "Initialize Trusted Agent"
                                onClicked: app_controller.initialize_local_trusted_agent(trusted_name.text, trusted_port.value)
                            }
                        }
                    }
                }
            }
        }

        Frame {
            visible: app_controller.last_error.length > 0
            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 8

                Label {
                    text: "Last error"
                    font.pixelSize: 20
                    font.bold: true
                }

                Label {
                    text: app_controller.last_error
                    color: "#7a130b"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }
        }

        Frame {
            visible: app_controller.configured
            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 12

                Label {
                    text: "Runtime"
                    font.pixelSize: 20
                    font.bold: true
                }

                Label {
                    text: "Local socket: " + app_controller.socket_path
                    wrapMode: Text.WrapAnywhere
                    Layout.fillWidth: true
                }

                Label {
                    text: "Peer id: " + app_controller.configured_peer_id
                    wrapMode: Text.WrapAnywhere
                    Layout.fillWidth: true
                }

                Label {
                    visible: app_controller.trusted_agent
                    text: "Enrollment fingerprint: " + app_controller.trusted_agent_fingerprint
                    wrapMode: Text.WrapAnywhere
                    Layout.fillWidth: true
                }
            }
        }

        Frame {
            visible: app_controller.trusted_agent
            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 16

                Label {
                    text: "Pending Enrollments"
                    font.pixelSize: 20
                    font.bold: true
                }

                Repeater {
                    model: app_controller.pending_requests

                    delegate: Frame {
                        required property var modelData

                        Layout.fillWidth: true

                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 8

                            Label {
                                text: modelData.name + " (" + modelData.peer_id + ")"
                                font.bold: true
                                Layout.fillWidth: true
                            }

                            Label {
                                text: "Verification code: " + modelData.verification_code
                                Layout.fillWidth: true
                            }

                            RowLayout {
                                Button {
                                    text: "Approve"
                                    onClicked: app_controller.approve_pending_request(modelData.request_id)
                                }

                                Button {
                                    text: "Reject"
                                    onClicked: app_controller.reject_pending_request(modelData.request_id)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    SettingsDialog {
        id: settings_dialog
        parent: window.contentItem
    }

    LogViewerDialog {
        id: log_viewer_dialog
        parent: window.contentItem
    }

    PeersDialog {
        id: peers_dialog
        parent: window.contentItem
    }

    AboutDialog {
        id: about_dialog
        parent: window.contentItem
    }

    Dialog {
        id: verification_dialog

        x: (window.width - width) / 2
        y: (window.height - height) / 2
        width: Math.min(window.width - 120, 460)
        modal: true
        closePolicy: Popup.NoAutoClose
        title: "Enrollment Verification"
        visible: app_controller.join_in_progress

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Compare this code with the trusted-agent device before approving enrollment."
                Layout.fillWidth: true
            }

            Frame {
                Layout.fillWidth: true

                Label {
                    anchors.centerIn: parent
                    text: app_controller.join_verification_code
                    font.pixelSize: 28
                    font.bold: true
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                BusyIndicator {
                    running: verification_dialog.visible
                }

                Label {
                    text: "Waiting for trusted-agent response..."
                    color: palette.mid
                    Layout.fillWidth: true
                }
            }
        }
    }
}
