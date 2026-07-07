# === Compilation stage ===

FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  cmake \
  git \
  build-essential

WORKDIR /portscan
COPY --exclude=build . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  && cmake --build build

# === Runtime stage ===

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  masscan \
  nmap

COPY --from=builder /portscan/build/executable /portscan/executable

COPY data/config.json /portscan/data/config.json

WORKDIR /portscan

# Run /portscan/executable -c /portscan/data/config.json.
ENTRYPOINT ["/portscan/executable"]
CMD ["-c", "/portscan/data/config.json"]

# For debug.
# ENTRYPOINT ["/bin/bash"]