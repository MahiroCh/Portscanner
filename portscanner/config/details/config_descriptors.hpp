#pragma once

#include <string>
#include <variant>
#include <functional>

#define CONFIG_FILEPATH_CLI_KEYS "c,config"

namespace portscan::config {

struct Config;

struct ConfigDescriptor {
  // Type names to Config settings real C++ types.
  enum ValueType {
    BOOL, // Name for bool.
    INT, // Name for int.
    STRING, // Name for std::string.
    STRING_VEC, // Name for std::vector<std::string>.
    INT_VEC, // Name for std::vector<int>.
  } type; 

  // JSON file key of the corresponding Config setting. 
  // Format: string.
  std::string json_key;
  
  // CLI key of the corresponding Config setting. 
  // Format: comma separated string like "c,config".
  std::string cli_keys;

  using Value = std::variant<
    bool, 
    int, 
    std::string, 
    std::vector<int>, 
    std::vector<std::string>
  >;
  // Function that knows how to assign Value to certain Config setting.
  std::function<void(Config&, const Value&)> applySetting;
};

extern const std::vector<ConfigDescriptor> config_descriptors;

} // namespace portscan::config