# `portscan`

A continuous network port scanner. Uses **masscan** for fast host/port discovery and **nmap** for service and banner detection.

## Usage

### Synopsis
 
`masscan [OPTION]`

### Options

`-h, --help`. Show help.

`-c, --config <PATH>`. Provide filepath to the user config for `portscan`. 
If not specified, `PATH` passed to the program is `./config.json`.

### Config file

`portscan` requires config file in JSON format with at least two values specified:

1) CIDR formatted IP(s) / IP ranges / IP subnets;
2) port(s) / port ranges.

Other values are optional. Default values are applied if user doesn't provide them,
see section below to find out which.

### Values format and description

**Format and defaults:**

See `config.example.json` file for all possible values and example formats.

| Field | Type | Default if not specified by user |
|---|---|---|
| `cidrs` | `string[]` | — (required) |
| `ports` | `string[]` | — (required) |
| `scan_interval` | `int` | `120` seconds |
| `masscan_rate` | `int` | `300` pkts/s |
| `nmap_threads` | `int` | `1` |
| `db_path` | `string` | `"portscan.db"` |
| `telegram_bot_token` | `string` | `""` (disabled) |
| `telegram_chat_id` | `string` | `""` (disabled) |

**Description of each value:**

1) `cidrs`. **Required.** List of IP addresses, ranges, or subnets in CIDR notation to scan.  
   Each element is a separate entry — you can mix single IPs (`"192.168.1.1"`), ranges (`"192.168.1.1-192.168.1.10"`), and subnets (`"192.168.0.0/16"`).  

2) `ports`. **Required.** List of ports or port ranges to scan.  
   Each element is a separate entry — single ports (`"443"`) and ranges (`"8000-9000"`) are both valid.  

3) `scan_interval`. Interval in seconds between scan cycles.  
   After each full scan completes, the program waits this long before starting the next one.  

4) `masscan_rate`. Number of packets per second masscan should send.  
   Higher values scan faster but may overwhelm your network. For home networks `100`–`500` is safe; for controlled environments you can go up to `10000` or more.  

5) `nmap_threads`. Number of concurrent nmap processes to run during service detection.  
   Higher values speed up fingerprinting but use more CPU.  

6) `db_path`. File path to the SQLite database where scan results are stored.  
   The database is created automatically if it doesn't exist.  

7) `telegram_bot_token`. Telegram Bot API token for sending notifications.  
   Leave empty (`""`) to disable Telegram notifications.  
   To create a bot and get a token, talk to [@BotFather](https://t.me/BotFather) on Telegram.  

8) `telegram_chat_id`. Telegram chat (user or group) ID to send notifications to.  
   Leave empty (`""`) if Telegram is disabled.  
   To find your chat ID, send a message to your bot and visit `https://api.telegram.org/bot<YourToken>/getUpdates`.  
