import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    required property var app_controller

    modal: true
    focus: true
    title: "Ego Graph"
    standardButtons: Dialog.Close
    x: 0
    y: 0
    width: parent ? parent.width : 1040
    height: parent ? parent.height : 760
    padding: 16

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: "Solid lines are direct connections from this node. Dotted lines are relay-reachable peers. Disconnected peers are placed outside the mesh without a connecting line."
            wrapMode: Text.WordWrap
            color: palette.mid
            font.pixelSize: 12
            Layout.fillWidth: true
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: "#f7f4ec"
            border.color: "#d2c7b6"

            ScrollView {
                anchors.fill: parent
                anchors.margins: 10
                clip: true
                contentWidth: graph_content.width
                contentHeight: graph_content.height
                ScrollBar.horizontal.policy: ScrollBar.AsNeeded
                ScrollBar.vertical.policy: ScrollBar.AsNeeded

                Item {
                    id: graph_content
                    width: app_controller.ego_graph_width
                    height: app_controller.ego_graph_height

                    Canvas {
                        id: graph_canvas
                        anchors.fill: parent

                        onPaint: {
                            const ctx = getContext("2d")
                            ctx.clearRect(0, 0, width, height)

                            const edges = app_controller.ego_graph_edges
                            for (let i = 0; i < edges.length; ++i) {
                                const edge = edges[i]
                                ctx.save()
                                ctx.beginPath()
                                if (edge.dotted) {
                                    ctx.setLineDash([6, 6])
                                } else {
                                    ctx.setLineDash([])
                                }
                                ctx.strokeStyle = edge.color
                                ctx.lineWidth = edge.dotted ? 1.5 : 2.5
                                ctx.moveTo(edge.x1, edge.y1)
                                ctx.lineTo(edge.x2, edge.y2)
                                ctx.stroke()
                                ctx.restore()
                            }
                        }

                        Connections {
                            target: app_controller
                            function onPeersChanged() {
                                graph_canvas.requestPaint()
                            }
                        }
                    }

                    Repeater {
                        model: app_controller.ego_graph_nodes

                        delegate: Item {
                            required property var modelData

                            x: modelData.x - width / 2
                            y: modelData.y - height / 2
                            width: Math.max(88, node_label.implicitWidth + 20)
                            height: 46

                            Rectangle {
                                anchors.fill: parent
                                radius: 14
                                color: modelData.is_local ? "#dbeef4" : "#fffaf0"
                                border.width: modelData.is_local ? 2.5 : 1.5
                                border.color: modelData.status_color
                            }

                            Column {
                                anchors.centerIn: parent
                                width: parent.width - 16
                                spacing: 1

                                Label {
                                    id: node_label
                                    width: parent.width
                                    horizontalAlignment: Text.AlignHCenter
                                    text: modelData.name
                                    font.bold: true
                                    font.pixelSize: 12
                                    elide: Text.ElideRight
                                }

                                Label {
                                    width: parent.width
                                    horizontalAlignment: Text.AlignHCenter
                                    text: modelData.status_label
                                    color: modelData.status_color
                                    font.pixelSize: 10
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                visible: app_controller.ego_graph_nodes.length === 0
                text: "No peer topology is available yet."
                color: palette.mid
                font.pixelSize: 12
            }
        }
    }
}
