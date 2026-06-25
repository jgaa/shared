qt_add_executable(sharedgui
    src/app_controller.h
    src/app_controller.cpp
    src/main.cpp
)

qt_add_qml_module(sharedgui
    URI Shared.Gui
    VERSION 1.0
    QML_FILES
        qml/AboutDialog.qml
        qml/LogSettings.qml
        qml/LogViewerDialog.qml
        qml/Main.qml
        qml/PeersDialog.qml
        qml/SettingsDialog.qml
)

target_link_libraries(sharedgui PRIVATE
    Qt6::Concurrent
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    sharedcore
)

shared_set_common_target_options(sharedgui)
