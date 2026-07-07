#include "config.hpp"
#include "network_utils.hpp"
#include "database.hpp"
#include "notifier.hpp"
#include "cxxopts.hpp"
#include "config.hpp"

#include <iostream>
#include <string>
#include <atomic>
#include <csignal>

static std::atomic<bool> terminate_signal{false};
static void handle_signal(int) {
  terminate_signal.store(true, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
  std::cout << std::unitbuf;
  
  cxxopts::Options options("portscan", "Utility that scans specified network ranges for open ports");
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
  std::cout << "User configuration loaded successfully.\n";

  // TODO: Add loop with cfg-specified time interval between scans.

  scanner::Config scan_cfg;
  scan_cfg.load_config(cfg);
  detector::Config detect_cfg;
  detect_cfg.load_config(cfg);

  signal(SIGINT,  handle_signal);
  signal(SIGTERM, handle_signal);

  scanner::ScanResult masscan_out = scanner::run_masscan(scan_cfg);
  detector::DetectResult nmap_out = detector::run_nmap(detect_cfg, masscan_out);

  std::cout << "\n=== Scan results ===\n";
  for (auto& svc : nmap_out) {
    std::cout << svc.ip << ':' << svc.port
              << "  service=" << svc.service_name
              << "  product=" << svc.product
              << "  version=" << svc.version
              << "  extrainfo=" << svc.extrainfo
              << '\n';
  }
  std::cout << "Total: " << nmap_out.size() << " open service(s)\n";

}
