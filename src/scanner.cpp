#include "scanner.hpp"
#include <tinyxml2.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <filesystem>
#include <iostream>

// Фиксированная скорость masscan в пакетах/сек.
// Для учебного стенда 1000 pps — безопасное значение.
static constexpr int MASSCAN_RATE = 1000;

// Запускает дочерний процесс с заданным списком аргументов.
// Возвращает строку со стандартным выводом (stdout + stderr).
static std::string run_process(const std::vector<std::string>& args) {
  if (args.empty()) throw std::runtime_error("run_process: пустой список аргументов");

  // Формируем C-массив указателей на строки для execvp
  std::vector<const char*> argv;
  for (const auto& a : args) argv.push_back(a.c_str());
  argv.push_back(nullptr);

  // Создаем пайп для чтения вывода дочернего процесса
  int pipefd[2];
  if (pipe(pipefd) == -1)
    throw std::runtime_error("pipe() завершился с ошибкой");

  pid_t pid = fork();
  if (pid == -1) {
    close(pipefd[0]);
    close(pipefd[1]);
    throw std::runtime_error("fork() завершился с ошибкой");
  }

  if (pid == 0) {
    // Дочерний процесс: перенаправляем stdout/stderr в пайп
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    execvp(argv[0], const_cast<char* const*>(argv.data()));
    _exit(127);  // Сюда доходим только если execvp не нашел исполняемый файл
  }

  // Родительский процесс: читаем вывод дочернего процесса
  close(pipefd[1]);
  std::string output;
  char buf[4096];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
    output.append(buf, n);
  close(pipefd[0]);

  int status;
  waitpid(pid, &status, 0);
  // Не выбрасываем исключение при ненулевом коде возврата —
  // masscan на некоторых системах возвращает ненулевой код даже при успехе
  return output;
}

std::vector<PortResult> run_masscan(
  const std::vector<std::string>& cidr_ranges,
  const std::vector<std::string>& ports
){
  // Формируем строку портов через запятую: "80,443,8080"
  std::string port_arg;
  for (size_t i = 0; i < ports.size(); ++i) {
    if (i) port_arg += ',';
    port_arg += ports[i];
  }

  // Временный XML-файл для вывода masscan
  char xml_path_buf[64];
  snprintf(xml_path_buf, sizeof(xml_path_buf), "/tmp/masscan_out_%d.xml", (int)getpid());
  std::string xml_path = xml_path_buf;

  // Аргументы для запуска masscan
  std::vector<std::string> args;
  args.push_back("masscan");
  for (const auto& cidr : cidr_ranges)
    args.push_back(cidr);
  args.push_back("-p");
  args.push_back(port_arg);
  args.push_back("--rate");
  args.push_back(std::to_string(MASSCAN_RATE));
  args.push_back("-oX");
  args.push_back(xml_path);
  args.push_back("--wait");
  args.push_back("3");  // Ждем 3 сек после отправки последнего пакета

  std::cerr << "[scanner] Запуск masscan: "
            << cidr_ranges.size() << " диапазон(а/ов), порты: " << port_arg << std::endl;

  run_process(args);  // Результат пишется в XML-файл, не в stdout

  // Разбираем XML-вывод masscan
  std::vector<PortResult> results;

  if (!std::filesystem::exists(xml_path)) {
    std::cerr << "[scanner] masscan не создал файл вывода (открытых портов нет?)" << std::endl;
    return results;
  }

  tinyxml2::XMLDocument doc;
  if (doc.LoadFile(xml_path.c_str()) != tinyxml2::XML_SUCCESS) {
    std::filesystem::remove(xml_path);
    std::cerr << "[scanner] Ошибка разбора XML-вывода masscan" << std::endl;
    return results;
  }

  // Структура XML masscan:
  // <nmaprun>
  //   <host>
  //     <address addr="1.2.3.4" addrtype="ipv4"/>
  //     <ports>
  //       <port protocol="tcp" portid="80">
  //         <state state="open"/>
  //       </port>
  //     </ports>
  //   </host>
  // </nmaprun>
  auto* root = doc.RootElement();  // <nmaprun>
  if (!root) {
    std::filesystem::remove(xml_path);
    return results;
  }

  for (
    auto* host = root->FirstChildElement("host");
    host;
    host = host->NextSiblingElement("host")
  ) {
    // Получаем IP-адрес хоста
    std::string ip;
    for (
      auto* addr = host->FirstChildElement("address");
      addr;
      addr = addr->NextSiblingElement("address")
    ) {
      const char* addrtype = addr->Attribute("addrtype");
      if (addrtype && strcmp(addrtype, "ipv4") == 0) {
        const char* a = addr->Attribute("addr");
        if (a) ip = a;
        break;
      }
    }
    if (ip.empty()) continue;

    auto* ports_elem = host->FirstChildElement("ports");
    if (!ports_elem) continue;

    for (
      auto* port = ports_elem->FirstChildElement("port");
      port;
      port = port->NextSiblingElement("port")
    ) {
      const char* proto  = port->Attribute("protocol");
      const char* portid = port->Attribute("portid");
      if (!proto || !portid) continue;

      auto* state = port->FirstChildElement("state");
      if (!state) continue;
      const char* st = state->Attribute("state");
      if (!st || strcmp(st, "open") != 0) continue;

      PortResult r;
      r.ip       = ip;
      r.port     = std::stoi(portid);
      r.protocol = proto;
      results.push_back(r);
    }
  }

  std::filesystem::remove(xml_path);
  std::cerr << "[scanner] masscan обнаружил " << results.size() << " открытых портов" << std::endl;
  return results;
}
