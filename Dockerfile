# Этап 1 — компиляция

FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  git \
  ca-certificates \
  libcurl4-openssl-dev \
  libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  && cmake --build build

# Этап 2 — запуск (не содержит инструменты для сборки, только runtime)

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  masscan \
  nmap \
  libcurl4 \
  libsqlite3-0 \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/portscan /app/portscan

# Пользовательский конфиг для настройки программы
# На случай, если будет запускаться без docker-compose.
COPY config.json /app/config.json

# База данных будет создана в /app/portscan.db
# Рекомендуется монтировать /app как volume для сохранения данных

ENTRYPOINT ["/app/portscan", "-c", "/app/config.json"]
