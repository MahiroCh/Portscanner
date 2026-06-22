# portscan

A continuous network port scanner written in C++17. Uses **masscan** for fast host/port discovery and **nmap** for service and banner detection. Results are stored in **SQLite** and new or changed ports/services trigger a **Telegram** notification.

---

## Features

- Continuous scan loop with configurable interval
- Fast port discovery via masscan
- Parallel service fingerprinting via nmap (banner grab + version detection)
- SQLite storage — tracks `first_seen` / `last_seen` per port
- Change detection: notifies only when something actually changes
- Telegram Bot notifications with exact port and service details:
  - New ports: `192.168.1.5:80/tcp  [http / Apache httpd 2.4.41]`
  - Changed services: `192.168.1.5:80/tcp  [nginx 1.18 -> Apache httpd 2.4.41]`
- Docker support — zero manual dependency setup

---

## Requirements (if used without Docker)

`GCC ≥ 10 or Clang ≥ 11`
`CMake ≥ 3.16`
`masscan`
`nmap`
`libcurl (dev)`
`libsqlite3 (dev)`

`nlohmann/json` and `tinyxml2` are downloaded automatically by CMake on first build.

Requires **root** or `CAP_NET_RAW` (masscan and nmap use raw sockets).

---

## Quick Start with Docker (recommended)

1. Clone the repository and enter the directory:

```bash
git clone https://github.com/MahiroCh/portscanner
cd portscanner
```

2. Edit `config.json` — set your CIDR ranges and Telegram credentials (see [Configuration](#configuration)).

3. Build and run:

```bash
docker compose up --build
```

The scanner starts immediately. Logs go to stdout. The SQLite database is saved to `./data/portscan.db` on your host.

To stop: `Ctrl+C` or `docker compose down`.

---

## Manual Build (without Docker)

```bash
sudo apt install -y build-essential cmake masscan nmap libcurl4-openssl-dev libsqlite3-dev

git clone https://github.com/MahiroCh/portscanner
cd portscanner
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Run:

```bash
sudo ./build/portscan -c config.json
```

---

## Configuration

All settings are in `config.json`:

```json
{
  "cidr_ranges": ["192.168.1.0/24"],
  "ports": ["21-23", "80", "443", "8080"],
  "scan_interval_seconds": 120,
  "db_path": "portscan.db",
  "telegram_bot_token": "YOUR_BOT_TOKEN",
  "telegram_chat_id": "YOUR_CHAT_ID"
}
```

| Field | Description | Required |
|---|---|---|
| `cidr_ranges` | List of CIDR ranges to scan | Yes |
| `ports` | Port list or ranges: `"80"`, `"1-1024"` | Yes |
| `scan_interval_seconds` | Seconds between full scan cycles | No (default: `120`) |
| `db_path` | Path to SQLite database file | No (default: `"portscan.db"`) |
| `telegram_bot_token` | Bot token from @BotFather | Yes |
| `telegram_chat_id` | Chat or group ID to receive alerts | Yes |

### Getting a Telegram bot token and chat ID

1. Open [@BotFather](https://t.me/BotFather) in Telegram → `/newbot` → copy the token.
2. Add the bot to your chat or group.
3. Send any message to the bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` — the `chat.id` field contains your chat ID.

---

## How It Works

```
while running:
  1. masscan  → discover open ports in CIDR ranges
  2. nmap     → fingerprint each port (parallel, 8 threads)
  3. SQLite   → compare with stored state
  4. Telegram → notify if new ports or service changes found
  5. sleep    → wait for next cycle
```

### masscan

Launched as a child process via `fork`/`execvp` with XML output:

```
masscan <cidr...> -p <ports> --rate 1000 -oX /tmp/masscan_out_<pid>.xml --wait 3
```

XML is parsed with **tinyxml2**.

### nmap

One nmap process per port, run in parallel (thread pool, 8 workers):

```
nmap -sT -sV --script=banner -p <port> -oX /tmp/nmap_<ip>_<port>_<pid>.xml --open -Pn -n --version-intensity 5 <ip>
```

### SQLite schema

```sql
CREATE TABLE services (
  ip           TEXT NOT NULL,
  port         INTEGER NOT NULL,
  protocol     TEXT NOT NULL,
  service_name TEXT DEFAULT '',
  product      TEXT DEFAULT '',
  version      TEXT DEFAULT '',
  banner       TEXT DEFAULT '',
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  PRIMARY KEY (ip, port, protocol)
);
```

### Telegram notification format

```
Port Scan Update

New open ports (2):
  • 192.168.1.10:80/tcp  [http / Apache httpd 2.4.41]
  • 192.168.1.15:22/tcp  [ssh / OpenSSH 8.9p1]

Changed services (1):
  • 192.168.1.10:443/tcp  [nginx 1.18.0 -> https / nginx 1.24.0]
```

---

## Project Structure

```
portscanner/
├── CMakeLists.txt
├── Dockerfile
├── docker-compose.yml
├── config.json
├── README.md
├── include/
│   ├── config.hpp
│   ├── scanner.hpp
│   ├── service_detector.hpp
│   ├── database.hpp
│   └── notifier.hpp
└── src/
    ├── main.cpp
    ├── config.cpp
    ├── scanner.cpp
    ├── service_detector.cpp
    ├── database.cpp
    └── notifier.cpp
```

---

## Limitations

- Requires root (or `CAP_NET_RAW`) — masscan and nmap use raw sockets.
- High `masscan_rate` on large CIDR ranges can saturate the network or be flagged as an attack. Use responsibly and only on networks you own or have permission to scan.
- UDP scanning (`-sU` in nmap) is slow by nature; the default port list in `config.json` targets TCP only.

