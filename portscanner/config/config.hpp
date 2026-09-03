#pragma once

#include <string>
#include <vector>

namespace usrcfg {

class Config {
public:
  std::vector<std::string> cidrs;      // IP-ranges for scan in CIDR format.
  std::vector<std::string> ports;      // List of ports and port ranges: "80", "1-1024", "443".
  std::string telegram_bot_token = ""; // Telegram-bot token.
  std::string telegram_chat_id = "";   // Telegram chat ID to send notifications to.
  std::string db_path = "portscan.db"; // Filepath to SQLite database.
  int scan_interval = 120;             // Interval between scans in seconds.
  int masscan_rate = 300;              // Masscan rate in packets/second.
  int nmap_threads = 1;                // Number of Nmap concurrent threads to use during scan.
};

// Load user-provided config into this program from JSON file.
Config load_config(const std::string& path);

} // namespace
