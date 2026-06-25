add_library(sharedservice STATIC
    src/daemon_application.h
    src/daemon_application.cpp
    src/enrollment_server.h
    src/enrollment_server.cpp
    src/peer_service.h
    src/peer_service.cpp
)

target_include_directories(sharedservice PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(sharedservice PUBLIC
    Qt6::Core
    Qt6::Network
    sharedcore
)

shared_set_common_target_options(sharedservice)

if(SHARED_BUILD_HEADLESS)
    qt_add_executable(shareddaemon
        src/main.cpp
    )

    target_link_libraries(shareddaemon PRIVATE
        Qt6::Core
        sharedservice
    )

    shared_set_common_target_options(shareddaemon)
endif()
