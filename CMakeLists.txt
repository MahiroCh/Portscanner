cmake_minimum_required(VERSION 3.16)
project(portscan VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(executable
  src/main.cpp
  src/config.cpp
  src/scanner.cpp
  src/database.cpp
  src/notifier.cpp
  src/service_detector.cpp
)

target_include_directories(executable PRIVATE
  ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(portscan PRIVATE
  -Wall -Wextra -Wpedantic
)
