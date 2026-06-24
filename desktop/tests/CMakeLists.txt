qt_add_executable(sharedcore_tests
    src/sharedcore_tests.cpp
)

target_link_libraries(sharedcore_tests PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Test
    sharedcore
)

shared_set_common_target_options(sharedcore_tests)

add_test(NAME sharedcore_tests COMMAND sharedcore_tests)
