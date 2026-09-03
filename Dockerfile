# === Compilation stage ===

FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  cmake \
  git \
  build-essential

WORKDIR /portscanner
COPY --exclude=build . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  && cmake --build build

# === Runtime stage ===

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  masscan \
  nmap

COPY --from=builder /portscanner/build/exe /portscanner/exe

COPY ./config.json /portscanner/config.json

WORKDIR /portscanner

ENTRYPOINT ["/portscanner/exe"]
CMD ["-c", "/portscanner/config.json"]

# For debug.
# ENTRYPOINT ["/bin/bash"]
