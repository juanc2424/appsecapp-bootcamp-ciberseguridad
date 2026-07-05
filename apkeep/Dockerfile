# apkeep (EFF) — descarga APKs por package_name desde APKPure/F-Droid/etc.
# Se ejecuta como contenedor efímero (docker compose run), igual que exodus,
# para no instalar nada en el SO del host.
FROM debian:bookworm-slim

ARG APKEEP_VERSION=1.0.0
# Selecciona el binario según la arquitectura del build (arm64 en Apple Silicon).
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && case "${TARGETARCH}" in \
      arm64) TRIPLE=aarch64-unknown-linux-gnu ;; \
      amd64) TRIPLE=x86_64-unknown-linux-gnu ;; \
      *) echo "arch no soportada: ${TARGETARCH}" && exit 1 ;; \
    esac \
 && curl -fSL -o /usr/local/bin/apkeep \
      "https://github.com/EFForg/apkeep/releases/download/${APKEEP_VERSION}/apkeep-${TRIPLE}" \
 && chmod +x /usr/local/bin/apkeep

WORKDIR /apks
ENTRYPOINT ["apkeep"]
CMD ["--help"]
