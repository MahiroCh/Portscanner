#include "config.hpp"
#include "network_utils.hpp"
#include "rapidxml.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <stdexcept>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

namespace detector {

// =============================================================================
// Logic
// =============================================================================

DetectResult run_nmap(Config cfg, const scanner::ScanResult& masscan_res) {
  if (masscan_res.empty()) {
    return DetectResult();
  }

  // Open the output file and write the XML declaration and opening root tag.
  std::string full_path = cfg.output_file_path + "." + cfg.output_file_format;
  std::ofstream out(full_path);
  if (!out) {
    throw std::runtime_error("Failed to open nmap output file: " + full_path);
  }
  out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmapruns>\n";

  for (auto& ep : masscan_res) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
      throw std::runtime_error("pipe() for nmap failed");
    }

    pid_t pid = fork();
    if (pid == -1) {
      throw std::runtime_error("fork() for nmap program failed");
    } else if (pid == 0) {
      // Command to be called for each IP:
      //   nmap -sV -sC -Pn -n -oX - -p <ports> <IP>
      // XML is written to stdout (-oX -), captured by the parent via pipe.

      close(pipefd[0]);
      dup2(pipefd[1], STDOUT_FILENO);
      close(pipefd[1]);

      ArgvBuilder cmd("nmap");
      cmd.add("-sV");
      cmd.add("-sC");
      cmd.add("-Pn");
      cmd.add("-n");
      cmd.add("-oX", "-");
      cmd.add("-p", ep.ports);
      cmd.add(ep.ip);

      char* const* argv = cmd.get_argv();
      if (execvp(argv[0], argv)) {
        // TODO: Make better error handling via pipe.
        _exit(1);
      }
    }

    // Parent: read nmap's XML output from the pipe, strip the XML declaration,
    // DOCTYPE, and comments, then append the <nmaprun> block to the output file.
    close(pipefd[1]);
    std::string block;
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
      block.append(buf, static_cast<size_t>(n));
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (!block.empty()) {
      // Strip <?xml ...?>, <!DOCTYPE ...>, and <!-- ... --> lines.
      size_t pos = 0;
      while (pos < block.size()) {
        size_t nl = block.find('\n', pos);
        if (nl == std::string::npos) nl = block.size();
        std::string line = block.substr(pos, nl - pos);
        size_t first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos ||
            (line.compare(first, 5, "<?xml") != 0 &&
             line.compare(first, 9, "<!DOCTYPE") != 0 &&
             line.compare(first, 4, "<!--") != 0)) {
          out << line;
          if (nl < block.size()) out << '\n';
        }
        pos = nl + 1;
      }
    }
  }

  out << "</nmapruns>\n";
  out.close();

  // Read the whole file back and parse it.
  return detector::parse_xml(full_path);
}

DetectResult parse_xml(const std::string& path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("Failed to open file with nmap output: " + path);
  }
  std::string ss;
  file.seekg(0, std::ios::end);
  ss.resize(file.tellg());
  file.seekg(0, std::ios::beg);
  file.read(ss.data(), ss.size());

  // Combined XML structure after stripping headers and wrapping:
  //
  // <?xml version="1.0" encoding="UTF-8"?>
  // <nmapruns>
  //   <nmaprun scanner="nmap" ...>
  //     <host ...>
  //       <address addr="IP" addrtype="ipv4"/>
  //       <ports>
  //         <port protocol="PROTO" portid="PORT_NUMBER">
  //           <state state="STATE" .../>
  //           <service name="http" product="nginx" version="1.31.2" .../>
  //         </port>
  //         ...
  //       </ports>
  //     </host>
  //     <runstats>...</runstats>
  //   </nmaprun>
  //   ...
  // </nmapruns>

  DetectResult detect_result;
  rapidxml::xml_document<> xml_content;
  xml_content.parse<0>(ss.data());

  rapidxml::xml_node<>* root = xml_content.first_node("nmapruns");
  if (!root) {
    throw std::runtime_error("Non-valid combined XML produced by nmap runs");
  }

  for (rapidxml::xml_node<>* nmaprun = root->first_node("nmaprun");
       nmaprun; nmaprun = nmaprun->next_sibling("nmaprun")) {

    for (rapidxml::xml_node<>* host = nmaprun->first_node("host");
         host; host = host->next_sibling("host")) {
      std::string ip;
      rapidxml::xml_node<>* address = host->first_node("address");
      if (address) {
        rapidxml::xml_attribute<>* addr = address->first_attribute("addr");
        if (addr) ip = addr->value();
      }
      if (ip.empty()) continue;

      rapidxml::xml_node<>* ports_node = host->first_node("ports");
      if (!ports_node) continue;

      for (rapidxml::xml_node<>* port_node = ports_node->first_node("port");
           port_node; port_node = port_node->next_sibling("port")) {
        rapidxml::xml_attribute<>* portid_attr = port_node->first_attribute("portid");
        if (!portid_attr) continue;

        rapidxml::xml_node<>* state_node = port_node->first_node("state");
        if (!state_node) continue;

        rapidxml::xml_attribute<>* state_attr = state_node->first_attribute("state");
        if (!state_attr || std::strcmp(state_attr->value(), "open") != 0) continue;

        DetectResult::ServiceInfo svc;
        svc.ip = ip;
        svc.port = static_cast<unsigned int>(std::atoi(portid_attr->value()));

        rapidxml::xml_node<>* service_node = port_node->first_node("service");
        if (service_node) {
          rapidxml::xml_attribute<>* name_attr = service_node->first_attribute("name");
          if (name_attr) svc.service_name = name_attr->value();

          rapidxml::xml_attribute<>* product_attr = service_node->first_attribute("product");
          if (product_attr) svc.product = product_attr->value();

          rapidxml::xml_attribute<>* version_attr = service_node->first_attribute("version");
          if (version_attr) svc.version = version_attr->value();

          rapidxml::xml_attribute<>* extrainfo_attr = service_node->first_attribute("extrainfo");
          if (extrainfo_attr) svc.extrainfo = extrainfo_attr->value();
        }

        detect_result.add(std::move(svc));
      }
    }
  }

  return detect_result;
}

// =============================================================================
// Implementations
// =============================================================================

// === Config ===

void Config::load_config(const usrcfg::Config& ucfg) {
  threads = static_cast<unsigned int>(ucfg.nmap_threads);
}

} // namespace