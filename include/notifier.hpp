#pragma once

#include "database.hpp"
#include <string>

// Отправляет уведомления в Telegram через Bot API.
class Notifier {
public:
  Notifier(const std::string& bot_token, const std::string& chat_id);

  // Отправляет сообщение об изменениях в сети.
  // Ничего не делает, если diff пустой.
  void notify(const DiffResult& diff);

private:
  // Отправляет произвольное текстовое сообщение через Telegram Bot API.
  void send_message(const std::string& text);

  std::string bot_token_;
  std::string chat_id_;
  bool credentials_invalid_ = false;
};
