#pragma once

#include <string>
#include <vector>

namespace portscan::config { 

// portscanner`s config. Every field has a sensible default except `cidrs
// and ports, which are mandatory.
class Config {
public:
  Config() : general(), notifier(general), masscan(general), nmap(general) {}

  // General portscanner configuration settings.
  struct General {
    std::string appdata_path; // Path to the directory where portscanner stores its files.
    std::string config_file_path; // Path to the user config file.
    std::string db_path; // Filepath to the SQLite database. Created if missing.
    std::vector<std::string> ips; // CIDR/IP/IP-range entries, e.g. "10.0.0.0/24", "10.0.0.1-10.0.0.50", "192.168.1.15".
    std::vector<std::string> ports; // Ports/port ranges, e.g. "443", "8000-8100".
    int scan_interval; // Seconds to wait between the end of one scan cycle and the start of the next.

    General()
      : appdata_path("./appdata/"),
        config_file_path("./config.json"),
        db_path(appdata_path + "database.db"),
        scan_interval(120)
    {}
  } general;

  // Notifier configuration for Telegram notifications.
  struct Notifier {
    std::string tgbot_token; // Telegram Bot API token. Empty disables Telegram notifications.
    std::string tgchat_id; // Telegram chat/user ID to notify. Empty disables Telegram notifications.
    std::string curl_exe_path; // Path to the curl executable, used to call the Telegram Bot API.
    std::string curl_exe_fallback_path; // Fallback path to the curl executable.

    Notifier(const General& general)
      : tgbot_token(""),
        tgchat_id(""),
        curl_exe_path("curl"),
        curl_exe_fallback_path(general.appdata_path + "curl")
    {}
  } notifier;

  // Configuration for masscan.
  struct Masscan {
    int masscan_rate; // Total Masscan send rate in packets/second.
    std::string masscan_exe_path; // Path to the Masscan executable.
    std::string masscan_exe_fallback_path; // Fallback path to the masscan executable.

    Masscan(const General& general)
      : masscan_rate(300),
        masscan_exe_path("masscan"),
        masscan_exe_fallback_path(general.appdata_path + "masscan")
    {}
  } masscan;

  // Configuration for nmap.
  struct Nmap {
    int nmap_threads; // Number of concurrent nmap worker processes.
    std::string nmap_exe_path; // Path to the nmap executable.
    std::string nmap_exe_fallback_path; // Fallback path to the nmap executable.

    Nmap(const General& general)
      : nmap_threads(1),
        nmap_exe_path("nmap"),
        nmap_exe_fallback_path(general.appdata_path + "nmap")
    {}
  } nmap;
};

} // namespace portscan::config