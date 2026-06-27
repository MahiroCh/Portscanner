#pragma once

#include "config.hpp"

#include <string>
#include <vector>

namespace scanner {

class Config {
public:
  std::vector<std::string> cidrs;                                          // CIDR IP address(es) or subnet(s) to scan.
  std::vector<std::string> ports;                                          // Ports or port ranges to scan.
  unsigned int rate;                                                       // `masscan` rate in packets/sec.
  const std::string output_file_format = "xml";                            // Scan results output file format.
  const std::string output_file_path = "/portscan/data/masscan.out.xml";   // Scan results output file path.

  void load_config(const usrcfg::Config&);
};

class ArgvBuilder {
private:
  std::vector<std::string> stred_args;
  std::vector<char*> chared_args;

public:
  ArgvBuilder(const std::string& program);
  void add(const std::string& i);
  void add(const std::string& flag, const std::string& value);
  void add(const std::string& flag, const unsigned int& value);
  void add(const std::string& flag, const std::vector<std::string>& list);
  char* const* get_argv();
};

class ScanResult {
private:
  struct PortInfo {
    std::string ip;        // Host IP.
    int port;              // Port.
    std::string transport; // Transport protocol: TCP or UDP.
  };
  std::vector<PortInfo> data;

public:
  PortInfo& operator[](int i);
  std::vector<PortInfo> get_raw();
};

// Run actual masscan to scan IP(s) or IP ranges for open ports.
ScanResult run_masscan(scanner::Config);

} // namespace
