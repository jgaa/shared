import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: window

    width: 900
    height: 600
    visible: true
    title: app_controller.app_name

    header: ToolBar {
        contentHeight: title_label.implicitHeight + 24

        Label {
            id: title_label

            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: 20
            text: "shared"
            font.pixelSize: 28
            font.bold: true
        }

        Button {
            anchors.verticalCenter: parent.verticalCenter
            anchors.right: parent.right
            anchors.rightMargin: 20
            text: "Settings"
            onClicked: settings_dialog.open()
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

                                placeholderText: "Device name"
                                Layout.fillWidth: true
                            }

                            TextField {
                                id: peer_host

                                placeholderText: "Trusted agent host or IP"
                                Layout.fillWidth: true
                            }

                            Label {
                                text: "TCP Port"
                            }

                            SpinBox {
                                id: peer_port

                                from: 1
                                to: 65535
                                value: 47123
                                editable: true
                            }

                            TextField {
                                id: peer_fingerprint

                                placeholderText: "Enrollment fingerprint (abcd-1234)"
                                Layout.fillWidth: true
                            }

                            Item {
                                Layout.fillHeight: true
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

                                placeholderText: "Device name"
                                Layout.fillWidth: true
                            }

                            Label {
                                text: "TCP Port"
                            }

                            SpinBox {
                                id: trusted_port

                                from: 1
                                to: 65535
                                value: 47123
                                editable: true
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

    Dialog {
        id: settings_dialog

        x: (window.width - width) / 2
        y: (window.height - height) / 2
        width: Math.min(window.width - 80, 760)
        height: Math.min(window.height - 80, 560)
        modal: true
        title: "Settings"

        onOpened: log_settings.reload()

        ColumnLayout {
            anchors.fill: parent
            spacing: 16

            TabBar {
                id: settings_tabs

                Layout.fillWidth: true

                TabButton {
                    text: "General"
                }

                TabButton {
                    text: "Logs"
                }
            }

            StackLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: settings_tabs.currentIndex

                ScrollView {
                    clip: true

                    ColumnLayout {
                        width: parent.width
                        spacing: 20

                        Frame {
                            Layout.fillWidth: true

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 10

                                Label {
                                    text: "Clipboard"
                                    font.pixelSize: 18
                                    font.bold: true
                                }

                                Label {
                                    text: "Clipboard Limit (MiB)"
                                }

                                SpinBox {
                                    value: app_controller.clipboard_limit_megabytes
                                    from: 1
                                    to: 8
                                    editable: true
                                    onValueModified: app_controller.clipboard_limit_megabytes = value
                                }
                            }
                        }

                        Frame {
                            Layout.fillWidth: true
                            Layout.fillHeight: true

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 10

                                Label {
                                    text: "Logging"
                                    font.pixelSize: 18
                                    font.bold: true
                                }

                                LogSettings {
                                    id: log_settings

                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
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

                        Label {
                            text: "Live Logs"
                            font.pixelSize: 18
                            font.bold: true
                        }

                        Label {
                            text: "The live log view is captured in memory for the current GUI process."
                            wrapMode: Text.WordWrap
                            color: palette.mid
                            Layout.fillWidth: true
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: "#142028"
                            radius: 8

                            ListView {
                                anchors.fill: parent
                                anchors.margins: 10
                                clip: true
                                model: app_controller.log_lines

                                delegate: Text {
                                    required property string modelData

                                    width: ListView.view.width
                                    text: modelData
                                    wrapMode: Text.WrapAnywhere
                                    color: "#d8edf3"
                                    font.family: "Monospace"
                                    font.pixelSize: 12
                                }
                            }
                        }
                    }
                }
            }

            DialogButtonBox {
                Layout.fillWidth: true
                standardButtons: DialogButtonBox.Close
                onRejected: settings_dialog.close()
            }
        }
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
            spacing: 16

            Label {
                text: "Compare this code with the trusted-agent device before approving enrollment."
                wrapMode: Text.WordWrap
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

            BusyIndicator {
                running: verification_dialog.visible
                Layout.alignment: Qt.AlignHCenter
            }

            Label {
                text: "Waiting for trusted-agent response..."
                color: palette.mid
                Layout.alignment: Qt.AlignHCenter
            }
        }
    }
}
