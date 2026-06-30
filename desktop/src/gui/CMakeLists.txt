add_library(sharedui STATIC
    src/app_controller.h
    src/app_controller.cpp
)

target_include_directories(sharedui PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

qt_add_qml_module(sharedui
    URI Shared.Gui
    VERSION 1.0
    QML_FILES
        qml/AboutDialog.qml
        qml/LogSettings.qml
        qml/LogViewerDialog.qml
        qml/Main.qml
        qml/PeersDialog.qml
        qml/SendClipboardDialog.qml
        qml/SendFilesDialog.qml
        qml/SettingsDialog.qml
)

qt_add_resources(sharedui "sharedgui_assets"
    PREFIX "/shared"
    FILES
        ../../../icons/shared-icon.svg
)

target_link_libraries(sharedui PUBLIC
    Qt6::Concurrent
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    sharedservice
    sharedcore
)

shared_set_common_target_options(sharedui)

qt_add_executable(sharedgui
    src/main.cpp
)

target_link_libraries(sharedgui PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    sharedui
    shareduiplugin
    shareduiplugin_init
    sharedcore
)

shared_set_common_target_options(sharedgui)
