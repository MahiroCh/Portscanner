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

    PortInfo(std::string i, int p, std::string t) : ip(i), port(p), transport(t) {}
  };
  std::vector<PortInfo> data;

public:
  class Iterator {
  private:
    PortInfo* ptr;

  public:
    explicit Iterator(PortInfo* p) : ptr(p) {}

    PortInfo& operator*() { return *ptr; }
    PortInfo* operator->() { return ptr; }

    Iterator& operator++() { ++ptr; return *this; }
    Iterator operator++(int) { Iterator prev = *this; ++ptr; return prev; }

    friend bool operator==(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const Iterator& lhs, const Iterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  class ConstIterator {
  private:
    const PortInfo* ptr;

  public:
    explicit ConstIterator(const PortInfo* p) : ptr(p) {}

    const PortInfo& operator*() const { return *ptr; }
    const PortInfo* operator->() const { return ptr; }

    ConstIterator& operator++() { ++ptr; return *this; }
    ConstIterator operator++(int) { ConstIterator prev = *this; ++ptr; return prev; }

    friend bool operator==(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr == rhs.ptr; }
    friend bool operator!=(const ConstIterator& lhs, const ConstIterator& rhs) { return lhs.ptr != rhs.ptr; }
  };

  Iterator begin() { return Iterator(data.data()); }
  Iterator end()   { return Iterator(data.data() + data.size()); }

  ConstIterator begin() const { return ConstIterator(data.data()); }
  ConstIterator end()   const { return ConstIterator(data.data() + data.size()); }

  PortInfo& operator[](int i) { return data[i]; }
  const PortInfo& operator[](int i) const { return data[i]; }

  std::vector<PortInfo>& get_raw() { return data; }
  const std::vector<PortInfo>& get_raw() const { return data; }

  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }

  void add(std::string ip, int port, std::string transport) {
    data.emplace_back(std::move(ip), port, std::move(transport));
  }
};

// Run actual masscan to scan IP(s) or IP ranges for open ports.
ScanResult run_masscan(const Config& cfg);

} // namespace
