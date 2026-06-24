set(shared_proto_output_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

add_library(sharedproto STATIC)

qt_add_protobuf(sharedproto
    OUTPUT_DIRECTORY "${shared_proto_output_dir}"
    PROTO_FILES
        "${CMAKE_SOURCE_DIR}/../proto/shared.proto"
    PROTO_INCLUDES
        "${CMAKE_SOURCE_DIR}/../proto"
)

target_link_libraries(sharedproto PUBLIC
    Qt6::Core
    Qt6::Protobuf
)

shared_set_common_target_options(sharedproto)

add_library(sharedcore STATIC
    include/shared/desktop/core/agent_configuration.h
    include/shared/desktop/core/app_metadata.h
    include/shared/desktop/core/app_paths.h
    include/shared/desktop/core/configuration_repository.h
    include/shared/desktop/core/enrollment_client.h
    include/shared/desktop/core/envelope_io.h
    include/shared/desktop/core/log_capture.h
    include/shared/desktop/core/logging.h
    include/shared/desktop/core/logging_controller.h
    include/shared/desktop/core/openssl_runner.h
    include/shared/desktop/core/pending_enrollment_repository.h
    include/shared/desktop/core/security_materials.h
    include/shared/desktop/core/settings_repository.h
    src/configuration_repository.cpp
    src/enrollment_client.cpp
    src/envelope_io.cpp
    src/log_capture.cpp
    src/logging_controller.cpp
    src/openssl_runner.cpp
    src/pending_enrollment_repository.cpp
    src/security_materials.cpp
    src/app_paths.cpp
    src/settings_repository.cpp
)

target_include_directories(sharedcore PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(sharedcore PUBLIC
    QCoro6::Core
    QCoro6::Network
    Qt6::Core
    Qt6::Network
    Qt6::Protobuf
    sharedproto
    logfault::logfault
    OpenSSL::Crypto
    OpenSSL::SSL
)

shared_set_common_target_options(sharedcore)
