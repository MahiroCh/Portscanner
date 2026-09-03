#include <portscanner/config/config.hpp>
#include <portscanner/config/builder.hpp>
#include <portscanner/config/parsers.hpp>
#include <iostream>
#include <string>
#include <atomic>
#include <csignal>

static std::atomic<bool> terminate_signal{false};
static void handle_signal(int) {
  terminate_signal.store(true, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
  using namespace portscan;

  config::CliParser cliParser;
  config::JsonParser jsonParser;

  config::Config config = config::ConfigBuilder()
      .attachParser(jsonParser)
      .attachParser(cliParser)
      .addSource(argc, argv)
      .build();
}