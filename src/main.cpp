#include "config.hpp"
#include "scanner.hpp"
#include "service_detector.hpp"
#include "database.hpp"
#include "notifier.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <stdexcept>

static std::atomic<bool> terminate_signal{true};
static void handle_signal(int) {
  terminate_signal = false;
}

static void print_usage(const char* prog) {
  std::cerr << "Использование: " << prog << " -c <config.json>\n"
            << "  -c <путь>   Путь к JSON-файлу конфигурации (обязательно)\n"
            << "  -h          Показать эту справку\n";
}

// Формирует однострочное описание сервиса: "http / Apache httpd 2.4.41".
static std::string fmt_svc(const ServiceInfo& si) {
  std::string s = si.service_name;
  if (!si.product.empty()) {
    if (!s.empty()) s += " / ";
    s += si.product;
  }
  if (!si.version.empty()) s += " " + si.version;
  return s.empty() ? "неизвестно" : s;
}

int main(int argc, char* argv[]) {
  std::string config_path;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    }
    if (arg == "-c" && i + 1 < argc) {
      config_path = argv[++i];
    }
  }

  if (config_path.empty()) {
    std::cerr << "Ошибка: требуется -c <config.json>\n";
    print_usage(argv[0]);
    return 1;
  }

  // Загрузка конфигурации
  Config cfg;
  try {
    cfg = load_config(config_path);
  } catch (const std::exception& e) {
    std::cerr << "Ошибка конфигурации: " << e.what() << std::endl;
    return 1;
  }

  std::cout << "[main] Конфигурация загружена. "
            << cfg.cidr_ranges.size() << " CIDR-диапазон(а/ов), "
            << "интервал=" << cfg.scan_interval_seconds << "с" << std::endl;

  // Установка обработчиков сигналов для корректного завершения
  signal(SIGINT,  handle_signal);
  signal(SIGTERM, handle_signal);

  // Инициализация компонентов
  Database db(cfg.db_path);
  Notifier notifier(cfg.telegram_bot_token, cfg.telegram_chat_id);
  
  // Главный цикл сканирования
  std::cout << "[main] Запуск непрерывного цикла сканирования. "
            << "Нажмите Ctrl+C для остановки." << std::endl;
  while (terminate_signal) {
    auto cycle_start = std::chrono::steady_clock::now();

    std::cout << "[main] === Цикл сканирования запущен ===" << std::endl;

    // Шаг 1: запуск masscan
    std::vector<PortResult> open_ports;
    try {
      open_ports = run_masscan(cfg.cidr_ranges, cfg.ports);
    } catch (const std::exception& e) {
      std::cerr << "[main] ошибка masscan: " << e.what() << std::endl;
      // Не прерываем цикл — ждем следующего
    }

    // Шаг 2: определение сервисов через nmap
    std::vector<ServiceInfo> services;
    if (!open_ports.empty()) {
      try {
        services = detect_services(open_ports);
      } catch (const std::exception& e) {
        std::cerr << "[main] ошибка определения сервисов: " << e.what() << std::endl;
      }
    }

    // Шаг 3: сравнение с БД и сохранение
    if (!services.empty()) {
      try {
        DiffResult diff = db.compare_and_update(services);

        // Вывод новых портов с деталями
        if (!diff.new_ports.empty()) {
          std::cout << "[main] Новые порты (" << diff.new_ports.size() << "):" << std::endl;
          for (const auto& si : diff.new_ports) {
            std::cout << "  + " << si.ip << ":" << si.port << "/" << si.protocol
                      << "  [" << fmt_svc(si) << "]" << std::endl;
          }
        }

        // Вывод изменившихся сервисов в формате "было -> стало"
        if (!diff.changed_services.empty()) {
          std::cout << "[main] Изменения сервисов (" << diff.changed_services.size() << "):" << std::endl;
          for (const auto& cs : diff.changed_services) {
            std::string old_str = cs.old_service;
            if (!cs.old_product.empty()) {
              if (!old_str.empty()) old_str += " / ";
              old_str += cs.old_product;
            }
            if (!cs.old_version.empty()) old_str += " " + cs.old_version;
            if (old_str.empty()) old_str = "неизвестно";

            std::cout << "  ~ " << cs.current.ip << ":" << cs.current.port
                      << "/" << cs.current.protocol
                      << "  [" << old_str << " -> " << fmt_svc(cs.current) << "]" << std::endl;
          }
        }

        if (diff.new_ports.empty() && diff.changed_services.empty()) {
          std::cout << "[main] Изменений не обнаружено." << std::endl;
        }

        // Шаг 4: уведомление через Telegram
        notifier.notify(diff);

      } catch (const std::exception& e) {
        std::cerr << "[main] ошибка БД/уведомления: " << e.what() << std::endl;
      }
    } else {
      std::cout << "[main] Открытых портов в этом цикле не найдено." << std::endl;
    }

    // Шаг 5: ожидание до следующего цикла с проверкой флага остановки
    auto cycle_end = std::chrono::steady_clock::now();
    auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
      cycle_end - cycle_start
    ).count();
    long sleep_s = cfg.scan_interval_seconds - (long)elapsed_s;

    std::cout << "[main] Цикл завершен за " << elapsed_s << "с. "
              << "Следующий скан через " << (sleep_s > 0 ? sleep_s : 0) << "с." << std::endl;

    // Спим по 1 секунде, чтобы оперативно реагировать на SIGINT
    for (long i = 0; i < sleep_s && terminate_signal; ++i)
      std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  std::cout << "[main] Завершение работы." << std::endl;
  return 0;
}
