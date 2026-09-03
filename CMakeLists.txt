cmake_minimum_required(VERSION 3.14)
project(portscanner VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(exe
  portscanner/main.cpp
  portscanner/config/builder.cpp
  portscanner/config/parsers.cpp
  portscanner/config/details/config_descriptors.cpp
  portscanner/database.cpp
  portscanner/notifier.cpp
  portscanner/subnet_scanner.cpp
  portscanner/service_detector.cpp
  external/sqlite/sqlite3.c
)

target_include_directories(exe PRIVATE
  ${CMAKE_SOURCE_DIR}/external
  ${CMAKE_SOURCE_DIR}
)

target_compile_options(exe PRIVATE
  -Wall -Wextra -Wpedantic
)
