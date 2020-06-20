cmake_minimum_required(VERSION 3.8)

foreach(policy
    CMP0074 # CMake 3.12
    )
  if(POLICY ${policy})
    cmake_policy(SET ${policy} NEW)
  endif()
endforeach()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

set(PROJECT_NAME dumpwow)

project(${PROJECT_NAME})

# build in Release-mode by default if not explicitly set
if( NOT CMAKE_BUILD_TYPE )
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

# threading library is required
find_package(Threads REQUIRED)

if ("${BLACKBONE_ROOT}" STREQUAL "")
    message(FATAL_ERROR "${PROJECT_NAME} requires BlackBone (https://github.com/DarthTon/Blackbone/)")
endif()

if (NOT EXISTS "${BLACKBONE_ROOT}/src/BlackBone")
    message(FATAL_ERROR "BlackBone not found at ${BLACKBONE_ROOT}")
endif()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(BLACKBONE_BUILD "Debug")
else()
    set(BLACKBONE_BUILD "Release")
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BLACKBONE_ARCH "x64")
else()
    set(BLACKBONE_ARCH "Win32")
endif()

set(BLACKBONE_LIB_DIR "${BLACKBONE_ROOT}/build/${BLACKBONE_ARCH}/${BLACKBONE_BUILD}")

if (NOT EXISTS "${BLACKBONE_LIB_DIR}")
    messsage(FATAL_ERROR "BlackBone library directory ${BLACKBONE_LIB_DIR} not found")
endif()

message(STATUS "BlackBone found at ${BLACKBONE_ROOT}, library directory ${BLACKBONE_LIB_DIR}")

add_definitions(-DUNICODE -D_UNICODE)
include_directories(Include
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${BLACKBONE_ROOT}/src"
)

link_directories("${BLACKBONE_LIB_DIR}")

#add_subdirectory(dll)
add_subdirectory(src)

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
    DESTINATION "${CMAKE_INSTALL_PREFIX}")