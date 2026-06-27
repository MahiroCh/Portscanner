#include "config.hpp"
#include "scanner.hpp"
#include "service_detector.hpp"
#include "database.hpp"
#include "notifier.hpp"
#include "cxxopts.hpp"
#include "config.hpp"
#include "scanner.hpp"

#include <iostream>
#include <string>
#include <atomic>
#include <csignal>

static std::atomic<bool> terminate_signal{false};
static void handle_signal(int) {
  terminate_signal.store(true, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
  cxxopts::Options options("portscan", "Utility that scans specified ranges for open ports");
  options.add_options()
    ("c,config", "Path to portscan JSON config file", cxxopts::value<std::string>()->default_value("./config.json"))
    ("h,help", "Show this help")
  ;
  auto result = options.parse(argc, argv);

  usrcfg::Config cfg;
  try {
    cfg = usrcfg::load_config(result["config"].as<std::string>());
  } catch (const std::exception& e) {
    std::cerr << "Configuration error: " << e.what() << std::endl;
    return 1;
  }
  std::cout << "User configuration loaded successfully\n";

  scanner::Config scan_cfg;
  scan_cfg.load_config(cfg);

  signal(SIGINT,  handle_signal);
  signal(SIGTERM, handle_signal);

  scanner::run_masscan(scan_cfg);

  // while(!terminate_signal.load(std::memory_order_relaxed)) {
  // }
}
