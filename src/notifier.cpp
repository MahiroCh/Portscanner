#include "notifier.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iostream>

using json = nlohmann::json;

// Вспомогательная функция: формирует строку описания сервиса вида "http / Apache httpd 2.4.41".
// Если все поля пусты — возвращает "неизвестно".
static std::string format_service(
  const std::string& service_name,
  const std::string& product,
  const std::string& version
){
  std::string result = service_name;
  if (!product.empty()) {
    if (!result.empty()) result += " / ";
    result += product;
  }
  if (!version.empty()) result += " " + version;
  return result.empty() ? "неизвестно" : result;
}

// libcurl write-callback: просто отбрасывает тело ответа.
static size_t write_discard(char*, size_t size, size_t nmemb, void*) {
  return size * nmemb;
}

Notifier::Notifier(const std::string& bot_token, const std::string& chat_id)
  : bot_token_(bot_token), chat_id_(chat_id)
{
  if (bot_token_.empty() || chat_id_.empty()) {
    credentials_invalid_ = true;
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

void Notifier::send_message(const std::string& text) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    std::cerr << "[notifier] curl_easy_init завершился с ошибкой" << std::endl;
    return;
  }

  std::string url = "https://api.telegram.org/bot" + bot_token_ + "/sendMessage";

  // Тело запроса в формате JSON
  json body;
  body["chat_id"]    = chat_id_;
  body["text"]       = text;
  body["parse_mode"] = "HTML";

  std::string body_str = body.dump();

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");

  long http_code = 0;

  curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body_str.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_discard);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

  CURLcode res = curl_easy_perform(curl);
  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    // 401 Unauthorized → невалидный bot_token
    // 400 Bad Request  → как правило, невалидный chat_id
    if (http_code == 401 || http_code == 400) {
      std::cerr << "[notifier] ошибка учетных данных Telegram (HTTP " 
                << http_code << "), исправьте данные и перезапустите программу для "
                << "включения функции уведомлений" << std::endl;
      credentials_invalid_ = true;
    }
  } else {
    // Ошибка не уровне сети, а не учетных данных Телеги (DNS, timeout, connection refused и т.д.)
    std::cerr << "[notifier] ошибка сети: " << curl_easy_strerror(res) << std::endl;
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
}

void Notifier::notify(const DiffResult& diff) {
  if (credentials_invalid_) return;
  if (diff.new_ports.empty() && diff.changed_services.empty()) return;

  std::ostringstream msg;
  msg << "<b>Обновление сканирования портов</b>\n";

  if (!diff.new_ports.empty()) {
    msg << "\n<b>Новые открытые порты (" << diff.new_ports.size() << "):</b>\n";
    for (const auto& si : diff.new_ports) {
      // Формат: ip:port/proto  [service / product version]
      msg << "  • " << si.ip << ":" << si.port << "/" << si.protocol
          << "  [" << format_service(si.service_name, si.product, si.version) << "]\n";
    }
  }

  if (!diff.changed_services.empty()) {
    msg << "\n<b>Изменения сервисов (" << diff.changed_services.size() << "):</b>\n";
    for (const auto& cs : diff.changed_services) {
      const auto& si = cs.current;
      // Формат: ip:port/proto  [было -> стало]
      std::string old_str = format_service(cs.old_service, cs.old_product, cs.old_version);
      std::string new_str = format_service(si.service_name, si.product, si.version);
      msg << "  • " << si.ip << ":" << si.port << "/" << si.protocol
          << "  [" << old_str << " -> " << new_str << "]\n";
    }
  }

  send_message(msg.str());
}
