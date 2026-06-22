#pragma once

#include "scanner.hpp"
#include <string>
#include <vector>

// Информация о сервисе, обнаруженном на открытом порту.
struct ServiceInfo {
  std::string ip;            // IP-адрес хоста
  int port;                  // Номер порта
  std::string protocol;      // Протокол: "tcp" или "udp"
  std::string service_name;  // Имя сервиса, например "http", "ssh"
  std::string product;       // Продукт, например "Apache httpd"
  std::string version;       // Версия, например "2.4.41"
  std::string banner;        // Сырой баннер (если доступен)
};

// Запускает nmap -sV для каждого PortResult параллельно (не более NMAP_THREADS потоков).
// Возвращает ServiceInfo для каждого порта.
std::vector<ServiceInfo> detect_services(
  const std::vector<PortResult>& ports
);
