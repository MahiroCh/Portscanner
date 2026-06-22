#pragma once

#include "service_detector.hpp"
#include <string>
#include <vector>

// Запись о сервисе, хранящаяся в базе данных.
struct StoredService {
  std::string ip;
  int port;
  std::string protocol;
  std::string service_name;
  std::string product;
  std::string version;
  std::string banner;
  std::string first_seen;  // ISO-8601 временная метка первого обнаружения
  std::string last_seen;   // ISO-8601 временная метка последнего обнаружения
};

// Описывает изменение сервиса на уже известном порту.
struct ChangedService {
  ServiceInfo current;      // Текущее состояние (после скана)
  std::string old_service;  // Прежнее имя сервиса
  std::string old_product;  // Прежний продукт
  std::string old_version;  // Прежняя версия
};

// Результат сравнения свежего скана с состоянием в базе данных.
struct DiffResult {
  std::vector<ServiceInfo>   new_ports;        // Порты, не присутствовавшие ранее
  std::vector<ChangedService> changed_services; // Порты, у которых изменился сервис/продукт/версия
};

// Класс для работы с базой данных SQLite.
class Database {
public:
  explicit Database(const std::string& db_path);
  ~Database();

  // Сравнивает свежие результаты скана с хранимым состоянием и обновляет базу.
  // Возвращает разницу (новые порты и изменившиеся сервисы).
  DiffResult compare_and_update(const std::vector<ServiceInfo>& fresh);

private:
  // Создает таблицу, если она еще не существует.
  void init_schema();

  struct Impl;
  Impl* impl_;
};
