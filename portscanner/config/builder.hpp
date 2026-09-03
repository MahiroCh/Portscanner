#pragma once

#include <portscanner/config/config.hpp>

namespace portscan::config {

class IFileParser;
class ICliParser;

class ConfigBuilder {
private:
  IFileParser* file_parser_{nullptr};
  std::string config_file_path_ = "";

  ICliParser* cli_parser_{nullptr};
  std::pair<int, const char* const*> cli_args_{0, nullptr};

  Config config_{};

  bool validateConfig() const;

public:
  ConfigBuilder();
  ConfigBuilder(IFileParser&, ICliParser&);
  
  ConfigBuilder& attachParser(IFileParser&);
  ConfigBuilder& attachParser(ICliParser&);

  ConfigBuilder& addSource(const std::string& config_file_path);
  ConfigBuilder& addSource(const int& argc, const char* const argv[]);

  Config build();
};

} // namespace portscan::config
