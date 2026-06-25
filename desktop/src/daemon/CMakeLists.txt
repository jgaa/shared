qt_add_executable(shareddaemon
    src/daemon_application.h
    src/daemon_application.cpp
    src/enrollment_server.h
    src/enrollment_server.cpp
    src/peer_service.h
    src/peer_service.cpp
    src/main.cpp
)

target_link_libraries(shareddaemon PRIVATE
    Qt6::Core
    Qt6::Network
    sharedcore
)

shared_set_common_target_options(shareddaemon)
