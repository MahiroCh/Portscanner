#include "network_utils.hpp"
#include "rapidxml.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

namespace scanner {

// =============================================================================
// Logic.
// =============================================================================

ScanResult run_masscan(const Config& cfg) {
  pid_t pid = fork();
  if (pid == -1) {
    throw std::runtime_error("fork() for masscan program failed");
  } else if (pid == 0) {
    // Command to be called: 
    //   masscan --ports <ports/port ranges> <CIDR IPs/IP ranges>
    //           --rate <rate> --output-format xml --output-filename <file_path>

    ArgvBuilder cmd("masscan");
    cmd.add("--ports", cfg.ports);
    cmd.add("", cfg.cidrs);
    cmd.add("--rate", cfg.rate);
    cmd.add("--output-format", cfg.output_file_format);
    cmd.add("--output-filename", cfg.output_file_path + "." + cfg.output_file_format);

    char* const* argv = cmd.get_argv();
    if (execvp(argv[0], argv)) {
      // TODO: Make better error handling via pipe.
      _exit(1);
    }
  }

  // TODO: Handle this.
  int status;
  waitpid(pid, &status, 0);
  
  return scanner::parse_xml(cfg.output_file_path + "." + cfg.output_file_format);
}

ScanResult parse_xml(const std::string& path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("Failed to open file with masscan output: " + path);
  }
  std::string ss;
  file.seekg(0, std::ios::end);
  ss.resize(file.tellg());
  file.seekg(0, std::ios::beg);
  file.read(ss.data(), ss.size());

  // Typical masscan XML output file structure:
  //
  // <?xml version="VERSION"?>
  // <!-- masscan vVERSION scan -->
  // <nmaprun scanner="masscan" start="NUMBER" version="VERSION"  xmloutputversion="VERSION">
  // 	<scaninfo type="TYPE" protocol="PROTOCOL" />
  //
  // 	<host endtime="NUMBER">
  // 		<address addr="IP_ADDRESS" addrtype="ADDRESS_TYPE"/>
  // 		<ports>
  //
  // 			<port protocol="PROTOCOL" portid="PORT">
  // 				<state state="STATE" reason="REASON" reason_ttl="TTL"/>
  // 			</port>
  //
  //      ...
  //
  //      <port ...>
  //        ...
  //      </port>
  //
  // 		</ports>
  // 	</host>
  //
  //  ...
  //
  // 	<host ...>
  // 		...
  // 	</host>
  //
  // 	<runstats>
  // 		<finished time="NUMBER" timestr="DATE_AND_TIME" elapsed="NUMBER" />
  // 		<hosts up="NUMBER" down="NUMBER" total="NUMBER" />
  // 	</runstats>
  // </nmaprun>

  ScanResult scan_result;
  rapidxml::xml_document<> xml_content;
  xml_content.parse<0>(ss.data()); 

  rapidxml::xml_node<>* root = xml_content.first_node("nmaprun");
  if (!root) {
    throw std::runtime_error("Non-valid XML file produced my masscan");
  }

  for (rapidxml::xml_node<>* host = root->first_node("host");
       host; host = host->next_sibling("host")) {
    std::string ip;
    rapidxml::xml_node<>* address = host->first_node("address");
    rapidxml::xml_attribute<>* addr = address->first_attribute("addr");
    if (addr) ip = addr->value();
    if (ip.empty()) continue;

    rapidxml::xml_node<>* ports_node = host->first_node("ports");
    if (!ports_node) continue;

    std::vector<unsigned int> ports;

    for (rapidxml::xml_node<>* port_node = ports_node->first_node("port");
         port_node; port_node = port_node->next_sibling("port")) {
      rapidxml::xml_attribute<>* portid_attr = port_node->first_attribute("portid");
      if (!portid_attr) continue;

      rapidxml::xml_node<>* state_node = port_node->first_node("state");
      if (!state_node) continue;

      rapidxml::xml_attribute<>* state_attr = state_node->first_attribute("state");
      if (!state_attr || std::strcmp(state_attr->value(), "open") != 0) continue;

      ports.emplace_back(std::atoi(portid_attr->value()));
    }
    scan_result.add(ip, ports);
  }

  return scan_result;
}

// =============================================================================
// Implementations.
// =============================================================================

// === Config. ===

void Config::load_config(const usrcfg::Config& ucfg) {
  if (ucfg.cidrs.empty()) {
    throw std::runtime_error("User config lacks IP(s) to scan for open ports");
  }
  if (ucfg.ports.empty()) {
    throw std::runtime_error("User config lacks port(s) to scan");
  }
  cidrs = ucfg.cidrs;
  ports = ucfg.ports;
  rate = ucfg.masscan_rate;
}

} // namespace