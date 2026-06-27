#include "scanner.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <iostream>
#include <vector>
#include <string>

namespace scanner {

// =============================================================================
// Logic
// =============================================================================

ScanResult run_masscan(Config cfg) {
  pid_t pid = fork();
  if (pid == -1) {
    throw std::runtime_error("fork() for masscan program failed");
  } else if (pid == 0) {
    /* Command to be called: 
       masscan --ports <ports/port ranges> <cidr ranges>  \\
               --rate <rate> --output-format xml --output-filename <file_path>
    */
    ArgvBuilder cmd("masscan");
    cmd.add("--ports", cfg.ports);
    cmd.add("", cfg.cidrs);
    cmd.add("--rate", cfg.rate);
    cmd.add("--output-format", cfg.output_file_format);
    cmd.add("--output-filename", cfg.output_file_path);

    char* const* argv = cmd.get_argv();
    if (execvp(argv[0], argv)) {
      // TODO: Make better error handling via pipe.
      _exit(1);
    }
  }

  int status;
  waitpid(pid, &status, 0);

  return ScanResult();
}

// #include <cstring>
  // if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
  //   throw std::runtime_error(
  //     "masscan exited with status " + std::to_string(WEXITSTATUS(status))
  //   );
  // }

// =============================================================================
// Implementations
// =============================================================================

// === Config ===

void Config::load_config(const usrcfg::Config& ucfg) {
  if (ucfg.cidrs.empty()) {
    throw std::runtime_error("User config lacks IP(s) to scan for open ports");
  }
  if (ucfg.ports.empty()) {
    throw std::runtime_error("User config lacks port(s) to scan");
  }
  cidrs = ucfg.cidrs;
  ports = ucfg.ports;
  rate = ucfg.masscan_rate;
}

// === ArgvBuilder ===

ArgvBuilder::ArgvBuilder(const std::string& program) {
  stred_args.push_back(program);
}

void ArgvBuilder::add(const std::string& i) {
  stred_args.push_back(i);
}

void ArgvBuilder::add(const std::string& flag, const std::string& value) {
  stred_args.push_back(flag);
  stred_args.push_back(value);
}

void ArgvBuilder::add(const std::string& flag, const unsigned int& value) {
  stred_args.push_back(flag);
  stred_args.push_back(std::to_string(value));
}

void ArgvBuilder::add(const std::string& flag, const std::vector<std::string>& list) {
  if (list.empty()) return;
  std::string str_concat = list[0];
  for (size_t i = 1; i < list.size(); ++i) {
    str_concat += "," + list[i];
  }
  if (!flag.empty()) stred_args.push_back(flag);
  stred_args.push_back(str_concat);
}

char* const* ArgvBuilder::get_argv() {
  chared_args.clear();
  chared_args.reserve(stred_args.size() + 1);
  for (auto& str : stred_args) {
    chared_args.push_back(const_cast<char*>(str.c_str()));
  }
  chared_args.push_back(nullptr);
  return chared_args.data();
}

// === ScanResult ===

ScanResult::PortInfo& ScanResult::operator[](int i) {
  return data[i];
}

std::vector<ScanResult::PortInfo> ScanResult::get_raw() {
  return data;
}

} // namespace
