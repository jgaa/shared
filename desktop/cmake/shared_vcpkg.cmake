# Enable automatically for native Windows builds, leaving other targets alone.
set(_shared_vcpkg_default OFF)
if(CMAKE_HOST_WIN32 AND
   (NOT CMAKE_SYSTEM_NAME OR CMAKE_SYSTEM_NAME STREQUAL "Windows"))
    set(_shared_vcpkg_default ON)
endif()
option(SHARED_USE_VCPKG "Use vcpkg for desktop native dependencies" ${_shared_vcpkg_default})
unset(_shared_vcpkg_default)

if(NOT SHARED_USE_VCPKG)
    return()
endif()

# Respect explicit toolchains, including Qt Creator kits and environment settings.
# Custom toolchains can integrate vcpkg themselves or be chainloaded by vcpkg.
if(CMAKE_TOOLCHAIN_FILE OR NOT "$ENV{CMAKE_TOOLCHAIN_FILE}" STREQUAL "")
    return()
endif()

set(_shared_vcpkg_root "C:/src/vcpkg")
if(NOT "$ENV{VCPKG_ROOT}" STREQUAL "")
    file(TO_CMAKE_PATH "$ENV{VCPKG_ROOT}" _shared_vcpkg_root)
endif()
set(SHARED_VCPKG_ROOT "${_shared_vcpkg_root}" CACHE PATH "Path to the vcpkg checkout")
unset(_shared_vcpkg_root)

if(NOT EXISTS "${SHARED_VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    message(FATAL_ERROR
        "vcpkg toolchain not found under '${SHARED_VCPKG_ROOT}'. "
        "Install and bootstrap vcpkg there, set -DSHARED_VCPKG_ROOT=/path/to/vcpkg "
        "or VCPKG_ROOT, or use -DSHARED_USE_VCPKG=OFF with dependencies provided separately.")
endif()

set(CMAKE_TOOLCHAIN_FILE "${SHARED_VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
    CACHE FILEPATH "CMake toolchain file" FORCE)
message(STATUS "shared_desktop: using vcpkg from ${SHARED_VCPKG_ROOT}")
