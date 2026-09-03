cmake_minimum_required(VERSION 3.14)
project(portscanner VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(executable
  src/main.cpp
  src/config.cpp
  src/subnet_scanner.cpp
  src/database.cpp
  src/notifier.cpp
  src/service_detector.cpp
)

target_include_directories(exe PRIVATE
  ${CMAKE_SOURCE_DIR}/external
  ${CMAKE_SOURCE_DIR}
)

target_compile_options(exe PRIVATE
  -Wall -Wextra -Wpedantic
)
