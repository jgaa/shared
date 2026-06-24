function(shared_set_common_target_options target_name)
    target_compile_features("${target_name}" PUBLIC cxx_std_20)

    target_compile_definitions("${target_name}" PRIVATE
        QT_NO_CAST_FROM_ASCII
        QT_NO_CAST_TO_ASCII
        QT_NO_URL_CAST_FROM_STRING
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options("${target_name}" PRIVATE
            -Wall
            -Wextra
            -Wpedantic
        )
    endif()
endfunction()
