#pragma once

#include <portscanner/config/details/iparsers.hpp>
#include <portscanner/config/details/config_descriptors.hpp>
#include <memory>

namespace portscan::config {

class JsonParser final : public IFileParser {
private:
  std::string cfg_file_path_;
  struct FileData; std::unique_ptr<FileData> file_data_;

public:
  JsonParser();
  ~JsonParser() override;

  void fetchFileData(const std::string& file_path) override;
  std::optional<ConfigDescriptor::Value> getValue(const std::string& key,
      ConfigDescriptor::ValueType expectedType) const override;
};

class CliParser final : public ICliParser {
private:
  int cli_argc_;
  const char* const* argv_;
  struct CliArgs; std::unique_ptr<CliArgs> cli_args_;

  std::optional<ConfigDescriptor::Value> getValueLogic(const std::string& key,
      ConfigDescriptor::ValueType expectedType) const;

public:
  CliParser();
  ~CliParser() override;

  void fetchCliArgs(const int& argc, const char* const argv[]) override;
  std::optional<ConfigDescriptor::Value> getValue(const std::string& key,
      ConfigDescriptor::ValueType expectedType) const override;
};

} // namespace portscan::config