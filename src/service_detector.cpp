#include "service_detector.hpp"
#include <tinyxml2.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <unistd.h>
#include <sys/wait.h>

// Количество параллельных потоков для запуска nmap.
// Для демонстрационного стенда 8 — разумный баланс между скоростью и нагрузкой.
static constexpr int NMAP_THREADS = 8;

// Запускает nmap для одного порта, записывает XML в /tmp.
// Возвращает путь к временному XML-файлу.
static std::string run_nmap_on_port(
  const std::string& ip,
  int port,
  const std::string& proto
){
  // Путь к временному XML-файлу с результатом
  char xml_path_buf[128];
  snprintf(
    xml_path_buf, sizeof(xml_path_buf),
    "/tmp/nmap_%s_%d_%d.xml", ip.c_str(), port, (int)getpid()
  );
  std::string xml_path = xml_path_buf;

  // Выбираем тип сканирования: UDP или TCP
  std::string scan_flag = (proto == "udp") ? "-sU" : "-sT";

  // Аргументы для nmap:
  //   -sT/-sU  — тип сканирования (TCP connect / UDP)
  //   -sV      — определение версии сервиса
  //   --script=banner — NSE-скрипт для захвата сырого баннера
  //   -p <N>   — сканировать только один конкретный порт
  //   -oX      — вывод в XML
  //   --open   — показывать только открытые порты
  //   -Pn      — пропустить ping (хост уже подтвержден masscan)
  //   -n       — без DNS-резолюции (быстрее)
  //   --version-intensity 5 — средняя глубина определения версии
  std::vector<std::string> args = {
    "nmap",
    scan_flag,
    "-sV",
    "--script=banner",
    "-p", std::to_string(port),
    "-oX", xml_path,
    "--open",
    "-Pn",
    "-n",
    "--version-intensity", "5",
    ip
  };

  // Формируем C-массив для execvp
  std::vector<const char*> argv;
  for (const auto& a : args) argv.push_back(a.c_str());
  argv.push_back(nullptr);

  int pipefd[2];
  if (pipe(pipefd) == -1) throw std::runtime_error("pipe() завершился с ошибкой");

  pid_t pid = fork();
  if (pid == -1) {
    close(pipefd[0]);
    close(pipefd[1]);
    throw std::runtime_error("fork() завершился с ошибкой");
  }
  if (pid == 0) {
    // Дочерний процесс
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    execvp(argv[0], const_cast<char* const*>(argv.data()));
    _exit(127);
  }
  close(pipefd[1]);

  // Дренируем вывод nmap (результаты нам нужны из XML-файла, а не из stdout)
  char buf[1024];
  while (read(pipefd[0], buf, sizeof(buf)) > 0) {}
  close(pipefd[0]);

  int status;
  waitpid(pid, &status, 0);

  return xml_path;
}

// Разбирает XML-файл nmap и возвращает ServiceInfo для указанного порта.
static ServiceInfo parse_nmap_xml(const std::string& xml_path, const PortResult& pr) {
  ServiceInfo si;
  si.ip       = pr.ip;
  si.port     = pr.port;
  si.protocol = pr.protocol;

  if (!std::filesystem::exists(xml_path)) return si;

  tinyxml2::XMLDocument doc;
  if (doc.LoadFile(xml_path.c_str()) != tinyxml2::XML_SUCCESS) {
    std::filesystem::remove(xml_path);
    return si;
  }

  // Структура XML nmap:
  // <nmaprun>
  //   <host>
  //     <ports>
  //       <port protocol="tcp" portid="80">
  //         <state state="open"/>
  //         <service name="http" product="Apache httpd" version="2.4.41" extrainfo="..."/>
  //         <script id="banner" output="..."/>
  //       </port>
  //     </ports>
  //   </host>
  // </nmaprun>

  auto* root = doc.RootElement();
  if (!root) { std::filesystem::remove(xml_path); return si; }

  auto* host = root->FirstChildElement("host");
  if (!host) { std::filesystem::remove(xml_path); return si; }

  auto* ports_elem = host->FirstChildElement("ports");
  if (!ports_elem) { std::filesystem::remove(xml_path); return si; }

  for (
    auto* port = ports_elem->FirstChildElement("port");
    port;
    port = port->NextSiblingElement("port")
  ) {
    const char* portid = port->Attribute("portid");
    if (!portid || std::stoi(portid) != pr.port) continue;

    auto* svc = port->FirstChildElement("service");
    if (svc) {
      const char* name    = svc->Attribute("name");
      const char* product = svc->Attribute("product");
      const char* version = svc->Attribute("version");
      const char* extra   = svc->Attribute("extrainfo");

      if (name)                       si.service_name = name;
      if (product)                    si.product = product;
      if (version)                    si.version = version;
      if (extra && strlen(extra) > 0) si.banner = extra;
    }

    // Предпочитаем сырой баннер из NSE-скрипта "banner"
    for (
      auto* script = port->FirstChildElement("script");
      script;
      script = script->NextSiblingElement("script")
    ) {
      const char* id = script->Attribute("id");
      if (id && strcmp(id, "banner") == 0) {
        const char* out = script->Attribute("output");
        if (out && strlen(out) > 0) si.banner = out;
        break;
      }
    }
    break;
  }

  std::filesystem::remove(xml_path);
  return si;
}

std::vector<ServiceInfo> detect_services(
  const std::vector<PortResult>& ports
){
  if (ports.empty()) return {};

  std::vector<ServiceInfo> results(ports.size());
  std::mutex cout_mtx;  // Мьютекс для безопасного вывода в stderr из нескольких потоков

  // Разделяемый индекс очереди задач (каждый поток берет следующий незанятый порт)
  std::mutex idx_mtx;
  size_t next_idx = 0;

  // Функция-воркер: обрабатывает порты по одному, пока очередь не опустеет
  auto worker = [&]() {
    while (true) {
      size_t i;
      {
        std::lock_guard<std::mutex> lock(idx_mtx);
        if (next_idx >= ports.size()) return;
        i = next_idx++;
      }
      const auto& pr = ports[i];
      {
        std::lock_guard<std::mutex> lk(cout_mtx);
        std::cerr << "[nmap] сканирование " << pr.ip << ":" << pr.port
                  << "/" << pr.protocol << std::endl;
      }
      try {
        std::string xml_path = run_nmap_on_port(pr.ip, pr.port, pr.protocol);
        results[i] = parse_nmap_xml(xml_path, pr);
      } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(cout_mtx);
        std::cerr << "[nmap] ошибка на " << pr.ip << ":" << pr.port
                  << " — " << e.what() << std::endl;
        // Заполняем минимальной информацией при сбое
        results[i].ip       = pr.ip;
        results[i].port     = pr.port;
        results[i].protocol = pr.protocol;
      }
    }
  };

  // Запускаем пул потоков; ограничиваем сверху числом портов
  int nthreads = std::min(NMAP_THREADS, (int)ports.size());
  std::vector<std::thread> threads;
  threads.reserve(nthreads);
  for (int t = 0; t < nthreads; ++t)
    threads.emplace_back(worker);
  for (auto& th : threads)
    th.join();

  return results;
}
