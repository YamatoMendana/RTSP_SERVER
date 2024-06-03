cmake_minimum_required(VERSION 3.0)

project(RTSP_SERVER)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -g )

set(CMAKE_OBJCXX_EXTENSIONS)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR}/include/transport)

add_subdirectory(src)