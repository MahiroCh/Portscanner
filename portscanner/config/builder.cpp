#include <portscanner/config/builder.hpp>
#include <portscanner/config/details/config_descriptors.hpp>
#include <portscanner/config/details/iparsers.hpp>
#include <stdexcept>
#include <optional>

namespace portscan::config {

ConfigBuilder::ConfigBuilder(IFileParser& fp, ICliParser& cp)
    : file_parser_(&fp), cli_parser_(&cp) {}

ConfigBuilder::ConfigBuilder() {};

ConfigBuilder& ConfigBuilder::attachParser(IFileParser& fp) {
  this->file_parser_ = &fp;
  return *this;
}

ConfigBuilder& ConfigBuilder::attachParser(ICliParser& cp) {
  this->cli_parser_ = &cp;
  return *this;
}

ConfigBuilder& ConfigBuilder::addSource(const std::string& config_file_path) {
  this->config_file_path_ = config_file_path;
  return *this;
}

ConfigBuilder& ConfigBuilder::addSource(const int& argc, const char* const argv[]) {
  this->cli_args_ = {argc, argv};
  return *this;
}

Config ConfigBuilder::build() {
  if (this->cli_parser_) {
    if (this->cli_args_.first == 0 || this->cli_args_.second == nullptr) {
      throw std::invalid_argument(
        "CLI parser provided, but no CLI arguments specified"
      );
    }

    this->cli_parser_->fetchCliArgs(this->cli_args_.first, this->cli_args_.second);
    this->config_file_path_= std::get<std::string>(
      this->cli_parser_->getValue(
        CONFIG_FILEPATH_CLI_KEYS, ConfigDescriptor::ValueType::STRING
      ).value_or(std::string(this->config_.general.config_file_path))
    );
  }

  if (this->file_parser_) {
    if (this->config_file_path_.empty()) {
      throw std::invalid_argument(
        "File parser provided, but no config file path specified"
      );
    }

    this->file_parser_->fetchFileData(this->config_file_path_);
  }
  
  for (auto& descriptor : config_descriptors) {
    std::optional<ConfigDescriptor::Value> value;
    if (this->cli_parser_) {
      value = this->cli_parser_->getValue(descriptor.cli_keys, descriptor.type);
    }
    if (!value.has_value() && this->file_parser_) {
      value = this->file_parser_->getValue(descriptor.json_key, descriptor.type);
    }
    if (value.has_value()) {
      descriptor.applySetting(this->config_, value.value());
    }
  }

  validateConfig();

  return this->config_; 
}

bool ConfigBuilder::validateConfig() const {
  // TODO: Actually only one of them non-specified should just print a warning 
  // and disable notifier, not throw exceptions (or should). We'll see later.
  if (!this->config_.notifier.tgbot_token.empty() && this->config_.notifier.tgchat_id.empty()) {
    throw std::invalid_argument(
      "Telegram bot token provided, but no chat ID specified"
    );
  }
  if (this->config_.notifier.tgbot_token.empty() && !this->config_.notifier.tgchat_id.empty()) {
    throw std::invalid_argument(
      "Telegram chat ID provided, but no bot token specified"
    );
  }

  if (this->config_.general.ips.empty()) {
    throw std::invalid_argument(
      "IP addresses/subnets/ranges must be specified"
    );
  }
  if (this->config_.general.ports.empty()) {
    throw std::invalid_argument(
      "Port numbers/ranges must be specified"
    );
  }
  if (this->config_.general.scan_interval < 0) {
    throw std::invalid_argument(
      "Scan interval must be non-negative"
    );
  }

  if (this->config_.masscan.masscan_rate <= 0) {
    throw std::invalid_argument(
      "Masscan rate must be positive (because it is a send rate in packets/second)"
    );
  }

  if (this->config_.nmap.nmap_threads <= 0) {
    throw std::invalid_argument(
      "Nmap threads must be at least 1"
    );
  }

  return true;
}

} // namespace portscan::config