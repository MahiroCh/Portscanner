#include <portscanner/config/config.hpp>
#include <portscanner/config/details/config_descriptors.hpp>
#include <stdexcept>

namespace portscan::config {

// Overload pattern for visitor method of std::variant that is used to initialize
// Config settings with the help of Config settings descriptors.
template<typename... Ts> struct CfgSetter : Ts... { using Ts::operator()...; };
template<typename... Ts> CfgSetter(Ts...) -> CfgSetter<Ts...>;

const std::vector<ConfigDescriptor> config_descriptors = {

  {
    .type = ConfigDescriptor::ValueType::STRING_VEC,
    .json_key = "ips",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::vector<std::string>& v) { 
          c.general.ips = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "IP addresses/ranges/subnets requires string or vector of strings, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING_VEC,
    .json_key = "ports",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::vector<std::string>& v) { 
          c.general.ports = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Port numbers/ranges requires string or vector of strings, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::INT,
    .json_key = "scan_interval",
    .cli_keys = "i,interval",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](int v) { 
          c.general.scan_interval = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Scan interval requires an integer, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::INT,
    .json_key = "port_discovery_speed",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](int v) { 
          c.masscan.masscan_rate = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Port discovery speed requires an integer, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "masscan_path",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.masscan.masscan_exe_path = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Masscan path requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "nmap_path",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.nmap.nmap_exe_path = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Nmap path requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "tgbot_token",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.notifier.tgbot_token = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Telegram bot token requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "tgchat_id",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.notifier.tgchat_id = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Telegram chat ID requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "curl_path",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.notifier.curl_exe_path = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Curl path requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::INT,
    .json_key = "svc_detection_speed",
    .cli_keys = "",
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](int v) { 
          c.nmap.nmap_threads = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Service detection speed requires an integer, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

  {
    .type = ConfigDescriptor::ValueType::STRING,
    .json_key = "",
    .cli_keys = CONFIG_FILEPATH_CLI_KEYS,
    .applySetting = [](Config& c, const ConfigDescriptor::Value& v) {
      std::visit(CfgSetter{
        [&c](const std::string& v) { 
          c.general.config_file_path = v; 
        },
        [](auto&&) { 
          throw std::invalid_argument(
            "Config file path requires a string, "
            "but parser has passed something else"
          ); 
        }
      }, v);
    },
  },

};

} // namespace portscan::config