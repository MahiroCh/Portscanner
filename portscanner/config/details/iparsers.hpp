#pragma once

#include <portscanner/config/details/config_descriptors.hpp>
#include <string>
#include <optional>

namespace portscan::config {

class IFileParser {
public:
  virtual ~IFileParser() = default;

  virtual void fetchFileData(const std::string& file_path) = 0;
  virtual std::optional<ConfigDescriptor::Value> getValue(const std::string& key,
      ConfigDescriptor::ValueType expectedType) const = 0;
};

class ICliParser {
public:
  virtual ~ICliParser() = default;

  virtual void fetchCliArgs(const int& argc, const char* const argv[]) = 0;
  virtual std::optional<ConfigDescriptor::Value> getValue(const std::string& key,
      ConfigDescriptor::ValueType expectedType) const = 0;
};

} // namespace portscan::config
