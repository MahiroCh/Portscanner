#include <portscanner/config/parsers.hpp>
#include <minjsoncpp.hpp>
#include <cxxopts.hpp>
#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace portscan::config {

struct JsonParser::FileData {
  FileData(const minjson::Value& json) : data(json) {}
  minjson::Value data; 
};

JsonParser::JsonParser() {}
JsonParser::~JsonParser() = default;

void JsonParser::fetchFileData(const std::string& path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("Failed to open configuration file: " + path);
  }
  std::ostringstream ss;
  ss << file.rdbuf();
  file.close();

  file_data_ = std::make_unique<FileData>(minjson::parse(ss.str()).value);
}

std::optional<ConfigDescriptor::Value> JsonParser::getValue(const std::string& key,
    ConfigDescriptor::ValueType expectedType) const {
  if (key.empty()) return std::nullopt;
  const auto* json_value = file_data_->data.resolve(key);
  if (!json_value) return std::nullopt;
  switch (expectedType) {
    case ConfigDescriptor::ValueType::BOOL:
      return json_value->asBool();
    case ConfigDescriptor::ValueType::INT:
      return static_cast<int>(json_value->asInt());
    case ConfigDescriptor::ValueType::STRING:
      return json_value->asString();
    case ConfigDescriptor::ValueType::STRING_VEC: {
      if (!json_value->isArray()) {
        throw std::runtime_error("Expected an array for JSON key: " + key);
      }
      std::vector<std::string> vec;
      for (const auto &item : json_value->asArray()) {
        vec.push_back(item.asString());
      }
      return vec;
    }
    case ConfigDescriptor::ValueType::INT_VEC: {
      if (!json_value->isArray()) {
        throw std::runtime_error("Expected an array for JSON key: " + key);
      }
      std::vector<int> vec;
      for (const auto &item : json_value->asArray()) {
        vec.push_back(item.asInt());
      }
      return vec;
    }
  }
}

} // namespace portscan::config

namespace portscan::config {

struct CliParser::CliArgs {
  CliArgs(const cxxopts::ParseResult& data) : data(data) {}
  cxxopts::ParseResult data; 
};

CliParser::CliParser() {}
CliParser::~CliParser() = default;

void CliParser::fetchCliArgs(const int& argc, const char* const argv[]) {
  cli_argc_ = argc;
  argv_ = argv;

  cxxopts::Options cli("", "");
  cli.allow_unrecognised_options();

  auto opts_adder = cli.add_options();
  for (const auto& d : config_descriptors) {
    if (d.cli_keys.empty()) continue;
    switch (d.type) {
      case ConfigDescriptor::ValueType::BOOL:
        opts_adder(d.cli_keys, "", cxxopts::value<bool>());
        break;
      case ConfigDescriptor::ValueType::INT:
        opts_adder(d.cli_keys, "", cxxopts::value<int>());
        break;
      case ConfigDescriptor::ValueType::STRING:
        opts_adder(d.cli_keys, "", cxxopts::value<std::string>());
        break;
      case ConfigDescriptor::ValueType::STRING_VEC:
        opts_adder(d.cli_keys, "", cxxopts::value<std::vector<std::string>>());
        break;
      case ConfigDescriptor::ValueType::INT_VEC:
        opts_adder(d.cli_keys, "", cxxopts::value<std::vector<int>>());
        break;
    }
  }

  cli_args_ = std::make_unique<CliArgs>(cli.parse(argc, argv));
}

std::optional<ConfigDescriptor::Value> CliParser::getValue(const std::string& key,
    ConfigDescriptor::ValueType expectedType) const {
  if (key.empty()) return std::nullopt;

  const auto comma_count = std::count(key.begin(), key.end(), ',');
  if (comma_count == 0) {
    if (!cli_args_->data.count(key)) return std::nullopt;
    return getValueLogic(key, expectedType);
  }

  if (comma_count > 1) {
    throw std::runtime_error("`key` parameter contains more than one comma: " + key);
  }

  const auto comma_pos = key.find(',');
  const std::string k1 = key.substr(0, comma_pos);
  const std::string k2 = key.substr(comma_pos + 1);

  const bool has_k1 = cli_args_->data.count(k1);
  const bool has_k2 = cli_args_->data.count(k2);

  if (has_k1 && has_k2) {
    throw std::runtime_error(
      "Both forms of the key are present ('" + k1 + "' and '" + k2 +
      "'); only one is allowed");
  }

  if (has_k1) return getValueLogic(k1, expectedType);
  if (has_k2) return getValueLogic(k2, expectedType);

  return std::nullopt;
}

std::optional<ConfigDescriptor::Value> CliParser::getValueLogic(const std::string& key,
    ConfigDescriptor::ValueType expectedType) const {
  switch (expectedType) {
    case ConfigDescriptor::ValueType::BOOL:
      return cli_args_->data[key].as<bool>();
    case ConfigDescriptor::ValueType::INT:
      return cli_args_->data[key].as<int>();
    case ConfigDescriptor::ValueType::STRING:
      return cli_args_->data[key].as<std::string>();
    case ConfigDescriptor::ValueType::STRING_VEC:
      throw std::runtime_error("STRING_VEC type is not supported for CLI arguments");
    case ConfigDescriptor::ValueType::INT_VEC:
      throw std::runtime_error("INT_VEC type is not supported for CLI arguments");
  }
}

} // namespace portscan::config
