# lean11 in a container (Podman or Docker). Build:   podman build -t lean11 .
#                                                    docker build -t lean11 -f Containerfile .
# Run with a folder for the ISOs and the working copy (about 40 GiB free), e.g.:
#   podman run --rm -it -v "$PWD:/data" lean11 download --lang en-US --out /data
#   podman run --rm -it -v "$PWD:/data" lean11 build /data/Win11_26H2_English_x64.iso --out /data/lean11.iso
#   podman run --rm -it -v "$PWD:/data" lean11 tui
FROM docker.io/library/rust:1-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p lean11 && strip target/release/lean11

FROM docker.io/library/debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/lean11 /usr/local/bin/lean11
WORKDIR /data
ENTRYPOINT ["lean11"]
CMD ["--help"]
