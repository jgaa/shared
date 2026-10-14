add_library(sharedui STATIC
    src/app_controller.h
    src/app_controller.cpp
    src/desktop_integration.h
    src/desktop_integration.cpp
)

target_include_directories(sharedui PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

set_source_files_properties(qml/SharedColors.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(sharedui
    URI Shared.Gui
    VERSION 1.0
    # Controllers are passed as QObject instances; this module exports QML
    # files, not C++ QML types. Avoid generating unused C++ registration code.
    NO_GENERATE_QMLTYPES
    NO_PLUGIN
    # Keep the embedded module on Qt's default import path regardless of
    # inherited Qt CMake policies or the app bundle's working directory.
    RESOURCE_PREFIX /qt/qml
    OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Shared/Gui"
    QML_FILES
        qml/SharedColors.qml
        qml/AboutDialog.qml
        qml/EgoGraphDialog.qml
        qml/LogSettings.qml
        qml/LogViewerDialog.qml
        qml/Main.qml
        qml/PeersDialog.qml
        qml/StitchedTopologyDialog.qml
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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sharedui PRIVATE Qt6::DBus)
endif()

shared_set_common_target_options(sharedui)

qt_add_executable(sharedgui
    src/tray_controller.h
    src/tray_controller.cpp
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
    sharedcore
)

shared_set_common_target_options(sharedgui)

if(APPLE)
    set_target_properties(sharedgui PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "${SHARED_APP_ID}"
        MACOSX_BUNDLE_BUNDLE_NAME "Shared"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    )

    # Qt's dynamically loaded OpenSSL backend searches Contents/Frameworks on
    # macOS, but does not discover Homebrew libraries already loaded by Shared.
    # Stage the libraries for terminal launches of the build-tree app too.
    if(OPENSSL_SSL_LIBRARY MATCHES "\\.dylib$" AND OPENSSL_CRYPTO_LIBRARY MATCHES "\\.dylib$")
        add_custom_command(TARGET sharedgui POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E make_directory
                "$<TARGET_BUNDLE_CONTENT_DIR:sharedgui>/Frameworks"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "$<TARGET_FILE:OpenSSL::SSL>"
                "$<TARGET_FILE:OpenSSL::Crypto>"
                "$<TARGET_BUNDLE_CONTENT_DIR:sharedgui>/Frameworks"
            COMMENT "Staging OpenSSL runtime libraries in the macOS app bundle"
            VERBATIM
        )
    endif()
endif()

install(TARGETS sharedgui
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

if(APPLE)
    qt_generate_deploy_qml_app_script(
        TARGET sharedgui
        OUTPUT_SCRIPT sharedgui_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${sharedgui_deploy_script})
endif()
