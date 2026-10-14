qt_add_executable(sharedcore_tests
    src/sharedcore_tests.cpp
)

target_link_libraries(sharedcore_tests PRIVATE
    Qt6::Core
    Qt6::Network
    Qt6::Test
    sharedcore
)

set_target_properties(sharedcore_tests PROPERTIES MACOSX_BUNDLE FALSE)

shared_set_common_target_options(sharedcore_tests)

add_test(NAME sharedcore_tests COMMAND sharedcore_tests)

qt_add_executable(peer_service_tests src/peer_service_tests.cpp)
target_link_libraries(peer_service_tests PRIVATE Qt6::Test sharedservice)
set_target_properties(peer_service_tests PROPERTIES MACOSX_BUNDLE FALSE)
shared_set_common_target_options(peer_service_tests)
add_test(NAME peer_service_tests COMMAND peer_service_tests)

if(SHARED_BUILD_GUI)
    qt_add_executable(transfer_notification_tests src/transfer_notification_tests.cpp)
    target_link_libraries(transfer_notification_tests PRIVATE
        Qt6::Test sharedui
    )
    set_target_properties(transfer_notification_tests PROPERTIES MACOSX_BUNDLE FALSE)
    shared_set_common_target_options(transfer_notification_tests)
    add_test(NAME transfer_notification_tests COMMAND transfer_notification_tests)
    set_tests_properties(transfer_notification_tests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
