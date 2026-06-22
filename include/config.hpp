#pragma once

#include <string>
#include <vector>

// Конфигурация программы, загружаемая из JSON-файла.
// masscan_rate и nmap_threads вынесены как константы в scanner.cpp / service_detector.cpp.
struct Config {
  std::vector<std::string> cidr_ranges;  // IP-диапазоны для сканирования в формате CIDR
  std::vector<std::string> ports;        // Список портов/диапазонов: "80", "1-1024", "443"
  int scan_interval_seconds;             // Интервал между циклами сканирования (секунды)
  std::string telegram_bot_token;        // Токен Telegram-бота
  std::string telegram_chat_id;          // ID чата для отправки уведомлений
  std::string db_path;                   // Путь к файлу базы данных SQLite
};

// Загружает конфигурацию из JSON-файла.
// Выбрасывает std::runtime_error при ошибке чтения или валидации.
Config load_config(const std::string& path);
