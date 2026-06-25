import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root

    anchors.centerIn: parent
    modal: true
    focus: true
    title: "Live Logs"
    standardButtons: Dialog.Close
    width: Math.min(parent ? parent.width - 80 : 900, 900)
    height: Math.min(parent ? parent.height - 80 : 620, 620)
    padding: 16

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

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
