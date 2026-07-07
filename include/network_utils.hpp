#pragma once

#include "config.hpp"

#include <string>
#include <vector>

// =============================================================================
// Subnet scanner.
// =============================================================================

namespace scanner {

class Config {
public:
  std::vector<std::string> cidrs;                                    // CIDR IP address(es) or subnet(s) to scan.
  std::vector<std::string> ports;                                    // Ports or port ranges to scan.
  unsigned int rate;                                                 // `masscan` rate in packets/sec.
  const std::string output_file_format = "xml";                      // Scan results output file format.
  const std::string output_file_path = "/portscan/data/masscan.out"; // Scan results output file path.

  void load_config(const usrcfg::Config&);
};

class ScanResult {
private:
  struct IpEndpoints {
    std::string ip;
    std::vector<unsigned int> ports;

    IpEndpoints(std::string i, std::vector<unsigned int> p) : ip(i), ports(p) {}
  };
  std::vector<IpEndpoints> data;

public:
  class Iterator {
  private:
    IpEndpoints* ptr;

  public:
    explicit Iterator(IpEndpoints* p) : ptr(p) {}
    IpEndpoints& operator*() { return *ptr; }
    IpEndpoints* operator->() { return ptr; }
    Iterator& operator++() { ++ptr; return *this; }
    Iterator operator++(int) { Iterator prev = *this; ++ptr; return prev; }
    friend bool operator==(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  class ConstIterator {
  private:
    const IpEndpoints* ptr;

  public:
    explicit ConstIterator(const IpEndpoints* p) : ptr(p) {}
    const IpEndpoints& operator*() const { return *ptr; }
    const IpEndpoints* operator->() const { return ptr; }
    ConstIterator& operator++() { ++ptr; return *this; }
    ConstIterator operator++(int) { ConstIterator prev = *this; ++ptr; return prev; }
    friend bool operator==(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  Iterator begin() { return Iterator(data.data()); }
  Iterator end() { return Iterator(data.data() + data.size()); }

  ConstIterator begin() const { return ConstIterator(data.data()); }
  ConstIterator end() const { return ConstIterator(data.data() + data.size()); }

  IpEndpoints& operator[](int i) { return data[i]; }
  const IpEndpoints& operator[](int i) const { return data[i]; }

  std::vector<IpEndpoints>& get_raw() { return data; }
  const std::vector<IpEndpoints>& get_raw() const { return data; }

  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }

  void add(std::string ip, std::vector<unsigned int> ports) {
    data.emplace_back(std::move(ip), std::move(ports));
  }
};

// Run actual masscan to scan IP(s) or IP ranges for open ports.
ScanResult run_masscan(const Config& cfg);

// Parse XML file produced by masscan.
ScanResult parse_xml(const std::string& path);

} // namespace

// =============================================================================
// Service detector.
// =============================================================================

namespace detector {

class Config {
public:
  unsigned int threads;
  const std::string output_file_format = "xml";                   // Scan results output file format.
  const std::string output_file_path = "/portscan/data/nmap.out"; // Scan results output file path.

  void load_config(const usrcfg::Config&);
};

class DetectResult {
public:
  struct ServiceInfo {
    std::string ip;
    unsigned int port;
    std::string service_name;
    std::string product;
    std::string version;
    std::string extrainfo;
  };

private:
  std::vector<ServiceInfo> data;

public:
  class Iterator {
  private:
    ServiceInfo* ptr;
  public:
    explicit Iterator(ServiceInfo* p) : ptr(p) {}
    ServiceInfo& operator*() { return *ptr; }
    ServiceInfo* operator->() { return ptr; }
    Iterator& operator++() { ++ptr; return *this; }
    Iterator operator++(int) { Iterator prev = *this; ++ptr; return prev; }
    friend bool operator==(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  class ConstIterator {
  private:
    const ServiceInfo* ptr;
    
  public:
    explicit ConstIterator(const ServiceInfo* p) : ptr(p) {}
    const ServiceInfo& operator*() const { return *ptr; }
    const ServiceInfo* operator->() const { return ptr; }
    ConstIterator& operator++() { ++ptr; return *this; }
    ConstIterator operator++(int) { ConstIterator prev = *this; ++ptr; return prev; }
    friend bool operator==(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  Iterator begin() { return Iterator(data.data()); }
  Iterator end() { return Iterator(data.data() + data.size()); }

  ConstIterator begin() const { return ConstIterator(data.data()); }
  ConstIterator end() const { return ConstIterator(data.data() + data.size()); }

  ServiceInfo& operator[](int i) { return data[i]; }
  const ServiceInfo& operator[](int i) const { return data[i]; }

  std::vector<ServiceInfo>& get_raw() { return data; }
  const std::vector<ServiceInfo>& get_raw() const { return data; }

  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }

  void add(ServiceInfo si) {
    data.push_back(std::move(si));
  }
};

// Run actual nmap to detect services on the given ip:ports from masscan results.
DetectResult run_nmap(Config, const scanner::ScanResult&);

// Parse XML file produced by nmap.
DetectResult parse_xml(const std::string& path);

} // namespace

// =============================================================================
// Common utilities.
// =============================================================================

class ArgvBuilder {
private:
  std::vector<std::string> stred_args;
  std::vector<char*> chared_args;

public:
  ArgvBuilder(const std::string& program) {
    stred_args.push_back(program);
  }

  void add(const std::string& i) {
    stred_args.push_back(i);
  }

  void add(const std::string& flag, const std::string& value) {
    stred_args.push_back(flag);
    stred_args.push_back(value);
  }

  void add(const std::string& flag, const unsigned int& value) {
    stred_args.push_back(flag);
    stred_args.push_back(std::to_string(value));
  }

  void add(const std::string& flag, const std::vector<std::string>& list) {
    if (list.empty()) return;
    std::string str_concat = list[0];
    for (size_t i = 1; i < list.size(); ++i) {
      str_concat += "," + list[i];
    }
    if (!flag.empty()) stred_args.push_back(flag);
    stred_args.push_back(str_concat);
  }

  void add(const std::string& flag, const std::vector<unsigned int>& list) {
    if (list.empty()) return;
    std::string str_concat = std::to_string(list[0]);
    for (size_t i = 1; i < list.size(); ++i) {
      str_concat += "," + std::to_string(list[i]);
    }
    if (!flag.empty()) stred_args.push_back(flag);
    stred_args.push_back(str_concat);
  }

  char* const* get_argv() {
    chared_args.clear();
    chared_args.reserve(stred_args.size() + 1);
    for (auto& str : stred_args) {
      chared_args.push_back(const_cast<char*>(str.c_str()));
    }
    chared_args.push_back(nullptr);
    return chared_args.data();
  }
};
