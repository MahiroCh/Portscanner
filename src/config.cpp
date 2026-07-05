#include "config.hpp"
#include "minjsoncpp.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace usrcfg {

// =============================================================================
// Implementations
// =============================================================================

// === Config ===

Config load_config(const std::string& path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("Failed to open configuration file: " + path);
  }
  std::ostringstream ss;
  ss << file.rdbuf();
  file.close();

  // TODO: There are different kinds of parse statuses and errors? that can be 
  // ignored or not. Check it: https://github.com/toughengineer/minjsoncpp#parsing
  auto json_content = minjson::parse(ss.str());
  if (json_content.status == minjson::ParsingResultStatus::Failure) {
    std::ostringstream ss;
    ss << "JSON parse failed\n";
    for (const auto &issue : json_content.issues) {
      ss << "offset " << issue.offset << ": "
         << issue.description << "\n";
    }
    throw std::runtime_error(ss.str());
  }

  const minjson::Value &json_root = json_content.value;
  Config cfg;

  if (const auto *scan_interval = json_root.resolve("scan_interval"); 
      scan_interval) {
    cfg.scan_interval = scan_interval->asInt();
  }

  if (const auto *db_path = json_root.resolve("db_path"); 
      db_path) {
    cfg.db_path = db_path->asString();
  }

  if (const auto *telegram_bot_token = json_root.resolve("telegram_bot_token");
      telegram_bot_token) {
    cfg.telegram_bot_token = telegram_bot_token->asString();
  }

  if (const auto *telegram_chat_id = json_root.resolve("telegram_chat_id");
      telegram_chat_id) {
    cfg.telegram_chat_id = telegram_chat_id->asString();
  }

  if (const auto *masscan_rate = json_root.resolve("masscan_rate");
      masscan_rate) {
    cfg.masscan_rate = masscan_rate->asInt();
  }

  if (const auto *nmap_threads = json_root.resolve("nmap_threads");
      nmap_threads) {
    cfg.nmap_threads = nmap_threads->asInt();
  }

  if (const auto *cidrs = json_root.resolve("cidrs");
      cidrs && cidrs->isArray()) {
    for (const auto &r : cidrs->asArray()) {
      cfg.cidrs.push_back(r.asString());
    }
  } else {
    throw std::runtime_error("Config is missing CIDR ranges for scan or it is not an array");
  }
  
  if (const auto *ports = json_root.resolve("ports");
      ports && ports->isArray()) {
    for (const auto &p : ports->asArray()) {
      cfg.ports.push_back(p.asString());
    }
  } else {
    throw std::runtime_error("Config is missing ports for scan or it is not an array");
  }

  return cfg;
}

} // namespace
