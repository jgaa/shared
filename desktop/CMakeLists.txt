cmake_minimum_required(VERSION 3.28)

project(shared_desktop VERSION 0.1.0 LANGUAGES CXX)

option(SHARED_BUILD_GUI "Build the Qt/QML desktop UI" ON)
option(SHARED_BUILD_HEADLESS "Build the headless service frontend" OFF)
option(SHARED_FLATPAK_BUILD "Build shared_desktop for Flatpak packaging" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

include(FetchContent)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SHARED_LOGFAULT_SOURCE_DIR "/home/jgaa/src/logfault" CACHE PATH "Use a local source dir for logfault")
if(SHARED_LOGFAULT_SOURCE_DIR AND EXISTS "${SHARED_LOGFAULT_SOURCE_DIR}/CMakeLists.txt")
    message(STATUS "shared_desktop: using local logfault from ${SHARED_LOGFAULT_SOURCE_DIR}")
    FetchContent_Declare(logfault SOURCE_DIR "${SHARED_LOGFAULT_SOURCE_DIR}")
else()
    FetchContent_Declare(logfault
        GIT_REPOSITORY https://github.com/jgaa/logfault.git
        GIT_TAG v0.8.5
    )
endif()
FetchContent_MakeAvailable(logfault)

set(SHARED_QCORO_SOURCE_DIR "" CACHE PATH "Use a local source dir for QCoro")
if(SHARED_QCORO_SOURCE_DIR AND EXISTS "${SHARED_QCORO_SOURCE_DIR}/CMakeLists.txt")
    message(STATUS "shared_desktop: using local QCoro from ${SHARED_QCORO_SOURCE_DIR}")
    FetchContent_Declare(qcoro SOURCE_DIR "${SHARED_QCORO_SOURCE_DIR}")
else()
    FetchContent_Declare(qcoro
        GIT_REPOSITORY https://github.com/qcoro/qcoro.git
        GIT_TAG v0.13.0
    )
endif()
set(QCORO_BUILD_EXAMPLES OFF CACHE BOOL "Disable QCoro examples in shared_desktop" FORCE)
set(QCORO_BUILD_TESTING OFF CACHE BOOL "Disable QCoro tests in shared_desktop" FORCE)
set(QCORO_WITH_QTDBUS OFF CACHE BOOL "Disable unused QCoro DBus support" FORCE)
set(QCORO_WITH_QTWEBSOCKETS OFF CACHE BOOL "Disable unused QCoro WebSockets support" FORCE)
set(QCORO_WITH_QTQUICK OFF CACHE BOOL "Disable unused QCoro QtQuick support" FORCE)
set(QCORO_WITH_QML OFF CACHE BOOL "Disable unused QCoro QML support" FORCE)
set(QCORO_WITH_QTTEST OFF CACHE BOOL "Disable unused QCoro QtTest support" FORCE)
FetchContent_MakeAvailable(qcoro)

set(SAFEKEEPING_BUILD_TESTS OFF CACHE BOOL "Disable SafeKeeping tests in shared_desktop" FORCE)
set(SAFEKEEPING_ENABLE_KWALLET ON CACHE BOOL "Enable KWallet support in shared_desktop" FORCE)
FetchContent_Declare(safekeeping
    GIT_REPOSITORY https://github.com/jgaa/SafeKeeping.git
    GIT_TAG 635466b1f3508265a13b35489f58849332fde0c1
)
FetchContent_MakeAvailable(safekeeping)

find_package(Qt6 6.10 REQUIRED COMPONENTS
    Core
    Core5Compat
    Network
    Protobuf
    ProtobufTools
)

set(shared_qt_optional_components)
if(SHARED_BUILD_GUI)
    list(APPEND shared_qt_optional_components
        Concurrent
        Gui
        Qml
        Quick
        QuickControls2
        Widgets
    )
endif()

if(BUILD_TESTING)
    list(APPEND shared_qt_optional_components Test)
endif()

if(shared_qt_optional_components)
    find_package(Qt6 6.10 REQUIRED COMPONENTS ${shared_qt_optional_components})
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

qt_standard_project_setup(REQUIRES 6.10)

include(CTest)

include(shared_common)

add_subdirectory(src/core)
add_subdirectory(src/daemon)
if(SHARED_BUILD_GUI)
    add_subdirectory(src/gui)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
