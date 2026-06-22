cmake_minimum_required(VERSION 3.16)
project(portscan VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Зависимости

include(FetchContent)

# nlohmann/json — header-only, загружается автоматически если не установлен в системе
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
)
FetchContent_MakeAvailable(nlohmann_json)

# tinyxml2 — парсер XML, загружается с GitHub
FetchContent_Declare(
  tinyxml2
  GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
  GIT_TAG        10.0.0
)
FetchContent_MakeAvailable(tinyxml2)

# libcurl — системный пакет (apt install libcurl4-openssl-dev)
find_package(CURL REQUIRED)

# SQLite3 — системный пакет (apt install libsqlite3-dev)
find_package(SQLite3 REQUIRED)

# pthreads
find_package(Threads REQUIRED)

# Исходные файлы

set(SOURCES
  src/main.cpp
  src/config.cpp
  src/scanner.cpp
  src/service_detector.cpp
  src/database.cpp
  src/notifier.cpp
)

add_executable(portscan ${SOURCES})

target_include_directories(portscan PRIVATE
  ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(portscan PRIVATE
  nlohmann_json::nlohmann_json
  tinyxml2::tinyxml2
  CURL::libcurl
  SQLite::SQLite3
  Threads::Threads
)

# Предупреждения компилятора
target_compile_options(portscan PRIVATE
  -Wall -Wextra -Wpedantic
)
