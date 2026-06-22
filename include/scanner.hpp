#pragma once

#include <string>
#include <vector>

// Результат сканирования одного открытого порта.
struct PortResult {
  std::string ip;        // IP-адрес хоста
  int port;              // Номер порта
  std::string protocol;  // Протокол: "tcp" или "udp"
};

// Запускает masscan по заданным CIDR-диапазонам и портам.
// Возвращает список обнаруженных открытых портов.
// Скорость сканирования задана константой MASSCAN_RATE в scanner.cpp.
// Выбрасывает std::runtime_error при сбое masscan.
std::vector<PortResult> run_masscan(
  const std::vector<std::string>& cidr_ranges,
  const std::vector<std::string>& ports
);
