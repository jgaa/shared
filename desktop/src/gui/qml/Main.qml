import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: window
    required property var app_controller

    function droppedUrlsToStrings(urls) {
        const selected = []
        for (const url of urls) {
            selected.push(url.toString())
        }
        return selected
    }

    width: 900
    height: 600
    visible: true
    title: app_controller.app_name
    footer: Rectangle {
        implicitHeight: 42
        color: "#f7f4ec"
        border.color: "#d2c7b6"
        border.width: 1

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            spacing: 12

            Rectangle {
                width: 12
                height: 12
                radius: 6
                color: app_controller.direct_peer_connected ? "#2e9d50" : "#b23a2e"
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: app_controller.direct_peer_connected ? "Direct peer connected" : "No direct peer connection"
                Layout.alignment: Qt.AlignVCenter
            }

            Rectangle {
                width: 1
                height: 18
                color: "#d2c7b6"
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignVCenter
                text: app_controller.status_message.length > 0
                    ? app_controller.status_message
                    : (app_controller.configured ? "Ready" : "Setup required")
                color: app_controller.status_message.length > 0 ? app_controller.status_color : palette.text
                wrapMode: Text.WordWrap
                elide: Text.ElideRight
            }
        }
    }
    menuBar: MenuBar {
        Menu {
            title: "File"

            Action {
                text: "Send Clipboard..."
                enabled: app_controller.configured
                onTriggered: send_clipboard_dialog.open()
            }

            Action {
                text: "Send Clipboard To All"
                enabled: app_controller.configured
                onTriggered: app_controller.send_clipboard_to_all()
            }

            Action {
                text: "Send Files..."
                enabled: app_controller.configured
                onTriggered: {
                    const selected = app_controller.select_files()
                    if (selected.length === 0) {
                        return
                    }

                    send_files_dialog.selectedFiles = selected
                    send_files_dialog.open()
                }
            }

            Action {
                text: "Send Files To All"
                enabled: app_controller.configured
                onTriggered: {
                    const selected = app_controller.select_files()
                    if (selected.length === 0) {
                        return
                    }

                    app_controller.send_files_to_all(selected)
                }
            }

            MenuSeparator {
            }

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
                text: "Reinitialize"
                enabled: app_controller.configured && !app_controller.join_in_progress
                onTriggered: reinitialize_dialog.open()
            }

            Action {
                text: "Decommission..."
                enabled: !app_controller.join_in_progress
                onTriggered: decommission_dialog.open()
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

    ScrollView {
        id: content_scroll

        anchors.fill: parent
        anchors.margins: 24
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: content_scroll.availableWidth
            spacing: 24

            Frame {
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 12

                    Label {
                        text: app_controller.configured
                            ? (app_controller.trusted_agent ? "Trusted Agent" : "Desktop shell")
                            : "First-run setup"
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

                    Label {
                        visible: app_controller.configured && app_controller.local_socket_enabled
                        text: "Local socket: " + app_controller.socket_path
                        wrapMode: Text.WrapAnywhere
                        Layout.fillWidth: true
                    }

                    Label {
                        visible: app_controller.configured
                        text: "Peer id: " + app_controller.configured_peer_id
                        wrapMode: Text.WrapAnywhere
                        Layout.fillWidth: true
                    }

                    RowLayout {
                        visible: app_controller.trusted_agent
                        Layout.fillWidth: true
                        spacing: 8

                        Label {
                            text: "Enrollment fingerprint: " + app_controller.trusted_agent_fingerprint
                            wrapMode: Text.WrapAnywhere
                            Layout.fillWidth: true
                        }

                        ToolButton {
                            icon.name: "edit-copy"
                            display: AbstractButton.IconOnly
                            text: "Copy enrollment fingerprint"
                            onClicked: app_controller.copy_to_clipboard(app_controller.trusted_agent_fingerprint)
                        }
                    }
                }
            }

            Frame {
                visible: !app_controller.configured
                Layout.fillWidth: true

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
                        currentIndex: setup_tabs.currentIndex

                        Item {
                            implicitHeight: join_existing_content.implicitHeight

                            ColumnLayout {
                                id: join_existing_content

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
                            }
                        }

                        Item {
                            implicitHeight: initialize_local_content.implicitHeight

                            ColumnLayout {
                                id: initialize_local_content

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
                visible: app_controller.configured
                Layout.fillWidth: true

                ColumnLayout {
                    anchors.fill: parent
                    spacing: 12

                    Label {
                        text: "Copy"
                        font.pixelSize: 20
                        font.bold: true
                    }

                    Label {
                        visible: !app_controller.copy_targets_available
                        text: "No peers are connected or currently reachable."
                        color: palette.mid
                        Layout.fillWidth: true
                    }

                    Flow {
                        Layout.fillWidth: true
                        spacing: 10

                        Button {
                            text: "Copy Clipboard To Peer"
                            enabled: app_controller.copy_targets_available
                            onClicked: send_clipboard_dialog.open()
                        }

                        Button {
                            text: "Copy Clipboard To All"
                            enabled: app_controller.copy_targets_available
                            onClicked: app_controller.send_clipboard_to_all()
                        }

                        Rectangle {
                            width: Math.max(drop_to_peer_label.implicitWidth + 32, 160)
                            height: 52
                            radius: 8
                            color: drop_to_peer.containsDrag ? "#dbe9d4" : "#f7f4ec"
                            border.color: app_controller.copy_targets_available ? "#9b8f7d" : "#d2c7b6"
                            border.width: 1

                            Label {
                                id: drop_to_peer_label
                                anchors.centerIn: parent
                                text: "Drop File To Peer"
                                color: app_controller.copy_targets_available ? palette.text : palette.mid
                            }

                            DropArea {
                                id: drop_to_peer

                                anchors.fill: parent
                                enabled: app_controller.copy_targets_available
                                onDropped: function(drop) {
                                    const selected = window.droppedUrlsToStrings(drop.urls)
                                    if (selected.length === 0) {
                                        return
                                    }

                                    send_files_dialog.selectedFiles = selected
                                    send_files_dialog.open()
                                }
                            }
                        }

                        Rectangle {
                            width: Math.max(drop_to_all_label.implicitWidth + 32, 160)
                            height: 52
                            radius: 8
                            color: drop_to_all.containsDrag ? "#dbe9d4" : "#f7f4ec"
                            border.color: app_controller.copy_targets_available ? "#9b8f7d" : "#d2c7b6"
                            border.width: 1

                            Label {
                                id: drop_to_all_label
                                anchors.centerIn: parent
                                text: "Drop File To All"
                                color: app_controller.copy_targets_available ? palette.text : palette.mid
                            }

                            DropArea {
                                id: drop_to_all

                                anchors.fill: parent
                                enabled: app_controller.copy_targets_available
                                onDropped: function(drop) {
                                    const selected = window.droppedUrlsToStrings(drop.urls)
                                    if (selected.length === 0) {
                                        return
                                    }

                                    app_controller.send_files_to_all(selected)
                                }
                            }
                        }
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

                                    Button {
                                        text: "Remove"
                                        onClicked: app_controller.remove_pending_request(modelData.request_id)
                                    }
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
        app_controller: window.app_controller
    }

    LogViewerDialog {
        id: log_viewer_dialog
        parent: window.contentItem
        app_controller: window.app_controller
    }

    PeersDialog {
        id: peers_dialog
        parent: window.contentItem
        app_controller: window.app_controller
    }

    SendClipboardDialog {
        id: send_clipboard_dialog
        parent: window.contentItem
        controller: app_controller
    }

    SendFilesDialog {
        id: send_files_dialog
        parent: window.contentItem
        controller: app_controller
    }

    AboutDialog {
        id: about_dialog
        parent: window.contentItem
        app_controller: window.app_controller
    }

    Dialog {
        id: reinitialize_dialog

        anchors.centerIn: parent
        modal: true
        title: "Reinitialize Local Agent"
        standardButtons: Dialog.Yes | Dialog.No

        onAccepted: app_controller.reinitialize_local_agent()

        contentItem: Label {
            width: 420
            wrapMode: Text.WordWrap
            text: "Clear this machine's current trusted-agent or peer enrollment and return to first-run setup? Reinitialize the new trusted agent first, then reinitialize every other agent before joining them to it."
        }
    }

    Dialog {
        id: decommission_dialog

        title: "Decommission"
        modal: true
        standardButtons: Dialog.Yes | Dialog.Cancel

        anchors.centerIn: parent
        width: Math.min(window.width * 0.75, 520)

        onAccepted: app_controller.decommission()

        contentItem: ColumnLayout {
            spacing: 12

            Label {
                text: "This will permanently remove the local vault, delete the configuration/settings file, and quit Shared."
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Label {
                text: "This action cannot be undone."
                font.bold: true
                color: "#7a130b"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
        }
    }

    Dialog {
        id: clipboard_approval_dialog

        x: (window.width - width) / 2
        y: (window.height - height) / 2
        width: Math.min(window.width - 120, 460)
        modal: true
        closePolicy: Popup.NoAutoClose
        title: "Approve Clipboard Transfer"
        visible: app_controller.clipboard_approval_pending

        onVisibleChanged: {
            if (visible) {
                window.show()
                window.raise()
                window.requestActivate()
            }
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Incoming clipboard text requires approval."
                Layout.fillWidth: true
            }

            Label {
                text: "Sender: " + app_controller.clipboard_approval_sender_name
                Layout.fillWidth: true
            }

            Label {
                text: "Size: " + app_controller.clipboard_approval_size_bytes + " bytes"
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true

                Item {
                    Layout.fillWidth: true
                }

                Button {
                    text: "Reject"
                    onClicked: app_controller.reject_clipboard_transfer()
                }

                Button {
                    text: "Approve"
                    onClicked: app_controller.approve_clipboard_transfer()
                }
            }
        }
    }

    Dialog {
        id: file_approval_dialog

        x: (window.width - width) / 2
        y: (window.height - height) / 2
        width: Math.min(window.width - 120, 500)
        modal: true
        closePolicy: Popup.NoAutoClose
        title: "Approve File Transfer"
        visible: app_controller.file_approval_pending

        onVisibleChanged: {
            if (visible) {
                window.show()
                window.raise()
                window.requestActivate()
            }
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 10

            Label {
                text: "Incoming file transfer requires approval."
                Layout.fillWidth: true
            }

            Label {
                text: "Sender: " + app_controller.file_approval_sender_name
                Layout.fillWidth: true
            }

            Label {
                text: "File: " + app_controller.file_approval_filename
                Layout.fillWidth: true
                wrapMode: Text.WrapAnywhere
            }

            Label {
                text: "Size: " + app_controller.file_approval_size_bytes + " bytes"
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true

                Item {
                    Layout.fillWidth: true
                }

                Button {
                    text: "Reject"
                    onClicked: app_controller.reject_file_transfer()
                }

                Button {
                    text: "Approve"
                    onClicked: app_controller.approve_file_transfer()
                }
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
