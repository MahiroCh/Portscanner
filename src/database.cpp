#include "database.hpp"
#include <sqlite3.h>
#include <stdexcept>
#include <iostream>
#include <ctime>

// Возвращает текущее время в формате ISO-8601 UTC (например, "2025-06-21T10:00:00Z").
static std::string now_iso() {
  time_t t = time(nullptr);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
  return buf;
}

// Внутренняя реализация (pimpl-идиома): хранит указатель на соединение SQLite.
struct Database::Impl {
  sqlite3* db = nullptr;
};

Database::Database(const std::string& db_path) : impl_(new Impl()) {
  int rc = sqlite3_open(db_path.c_str(), &impl_->db);
  if (rc != SQLITE_OK) {
    throw std::runtime_error(
      "Не удалось открыть SQLite БД: " + std::string(sqlite3_errmsg(impl_->db))
    );
  }
  // WAL-режим улучшает параллельную запись
  sqlite3_exec(impl_->db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
  init_schema();
}

Database::~Database() {
  if (impl_->db) sqlite3_close(impl_->db);
  delete impl_;
}

void Database::init_schema() {
  const char* sql = R"(
    CREATE TABLE IF NOT EXISTS services (
      ip           TEXT NOT NULL,
      port         INTEGER NOT NULL,
      protocol     TEXT NOT NULL,
      service_name TEXT DEFAULT '',
      product      TEXT DEFAULT '',
      version      TEXT DEFAULT '',
      banner       TEXT DEFAULT '',
      first_seen   TEXT NOT NULL,
      last_seen    TEXT NOT NULL,
      PRIMARY KEY (ip, port, protocol)
    );
  )";
  char* err = nullptr;
  int rc = sqlite3_exec(impl_->db, sql, nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string msg = "Ошибка инициализации схемы БД: ";
    msg += err ? err : "неизвестная ошибка";
    sqlite3_free(err);
    throw std::runtime_error(msg);
  }
}

DiffResult Database::compare_and_update(const std::vector<ServiceInfo>& fresh) {
  DiffResult diff;
  const std::string now = now_iso();

  // Выполняем все операции в одной транзакции для производительности
  sqlite3_exec(impl_->db, "BEGIN;", nullptr, nullptr, nullptr);

  for (const auto& si : fresh) {
    // Ищем существующую запись по первичному ключу (ip, port, protocol)
    const char* sel_sql =
      "SELECT service_name, product, version, banner "
      "FROM services WHERE ip=? AND port=? AND protocol=?;";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(impl_->db, sel_sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, si.ip.c_str(),       -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 2, si.port);
    sqlite3_bind_text(stmt, 3, si.protocol.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);

    if (rc == SQLITE_DONE) {
      // Новый порт — записи в БД еще нет
      sqlite3_finalize(stmt);

      const char* ins_sql =
        "INSERT INTO services"
        "(ip,port,protocol,service_name,product,version,banner,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?,?);";
      sqlite3_stmt* ins = nullptr;
      sqlite3_prepare_v2(impl_->db, ins_sql, -1, &ins, nullptr);
      sqlite3_bind_text(ins, 1, si.ip.c_str(),           -1, SQLITE_STATIC);
      sqlite3_bind_int (ins, 2, si.port);
      sqlite3_bind_text(ins, 3, si.protocol.c_str(),     -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 4, si.service_name.c_str(), -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 5, si.product.c_str(),      -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 6, si.version.c_str(),      -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 7, si.banner.c_str(),       -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 8, now.c_str(),             -1, SQLITE_STATIC);
      sqlite3_bind_text(ins, 9, now.c_str(),             -1, SQLITE_STATIC);
      sqlite3_step(ins);
      sqlite3_finalize(ins);

      diff.new_ports.push_back(si);

    } else if (rc == SQLITE_ROW) {
      // Существующий порт — сравниваем сервис
      std::string old_svc     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
      std::string old_product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
      std::string old_version = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
      sqlite3_finalize(stmt);

      bool changed = (old_svc     != si.service_name) ||
                     (old_product != si.product)       ||
                     (old_version != si.version);

      // Всегда обновляем last_seen и текущую информацию о сервисе
      const char* upd_sql =
        "UPDATE services SET service_name=?, product=?, version=?, banner=?, last_seen=? "
        "WHERE ip=? AND port=? AND protocol=?;";
      sqlite3_stmt* upd = nullptr;
      sqlite3_prepare_v2(impl_->db, upd_sql, -1, &upd, nullptr);
      sqlite3_bind_text(upd, 1, si.service_name.c_str(), -1, SQLITE_STATIC);
      sqlite3_bind_text(upd, 2, si.product.c_str(),      -1, SQLITE_STATIC);
      sqlite3_bind_text(upd, 3, si.version.c_str(),      -1, SQLITE_STATIC);
      sqlite3_bind_text(upd, 4, si.banner.c_str(),       -1, SQLITE_STATIC);
      sqlite3_bind_text(upd, 5, now.c_str(),             -1, SQLITE_STATIC);
      sqlite3_bind_text(upd, 6, si.ip.c_str(),           -1, SQLITE_STATIC);
      sqlite3_bind_int (upd, 7, si.port);
      sqlite3_bind_text(upd, 8, si.protocol.c_str(),     -1, SQLITE_STATIC);
      sqlite3_step(upd);
      sqlite3_finalize(upd);

      if (changed) {
        // Сохраняем старые значения для отображения в формате "было -> стало"
        ChangedService cs;
        cs.current     = si;
        cs.old_service = old_svc;
        cs.old_product = old_product;
        cs.old_version = old_version;
        diff.changed_services.push_back(cs);
      }
    } else {
      sqlite3_finalize(stmt);
    }
  }

  sqlite3_exec(impl_->db, "COMMIT;", nullptr, nullptr, nullptr);
  return diff;
}
