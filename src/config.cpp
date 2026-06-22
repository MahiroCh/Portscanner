#include "config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

Config load_config(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) {
    throw std::runtime_error("Не удалось открыть файл конфигурации: " + path);
  }

  json j;
  try {
    f >> j;
  } catch (const json::exception& e) {
    throw std::runtime_error(std::string("Ошибка разбора JSON: ") + e.what());
  }

  Config cfg;

  // Обязательные поля
  if (!j.contains("cidr_ranges") || !j["cidr_ranges"].is_array())
    throw std::runtime_error("В конфиге отсутствует массив 'cidr_ranges'");
  for (const auto& r : j["cidr_ranges"])
    cfg.cidr_ranges.push_back(r.get<std::string>());

  if (!j.contains("ports") || !j["ports"].is_array())
    throw std::runtime_error("В конфиге отсутствует массив 'ports'");
  for (const auto& p : j["ports"])
    cfg.ports.push_back(p.get<std::string>());

  if (!j.contains("telegram_bot_token"))
    throw std::runtime_error("В конфиге отсутствует 'telegram_bot_token'");
  cfg.telegram_bot_token = j["telegram_bot_token"].get<std::string>();

  if (!j.contains("telegram_chat_id"))
    throw std::runtime_error("В конфиге отсутствует 'telegram_chat_id'");
  cfg.telegram_chat_id = j["telegram_chat_id"].get<std::string>();

  // Необязательные поля с умолчаниями
  cfg.scan_interval_seconds = j.value("scan_interval_seconds", 120);
  cfg.db_path               = j.value("db_path", "portscan.db");

  if (cfg.cidr_ranges.empty())
    throw std::runtime_error("'cidr_ranges' не должен быть пустым");
  if (cfg.ports.empty())
    throw std::runtime_error("'ports' не должен быть пустым");

  return cfg;
}
