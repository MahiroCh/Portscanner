#pragma once

#include "config.hpp"
#include "subnet_scanner.hpp"

namespace detector {

class Config {
public:

  // TODO: Config...

  void load_config(const usrcfg::Config&);
};

class DetectResult {

  // TODO: Result...

};

// Run actual nmap detect services on the given ip:ports.
DetectResult run_nmap(Config, const scanner::ScanResult&);

} // namespace