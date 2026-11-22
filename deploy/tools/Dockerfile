# OpenTofu + Terragrunt in one image, so the host needs only Docker.
FROM ghcr.io/opentofu/opentofu:1.13.9-minimal AS tofu

FROM alpine:3.22
ARG TARGETARCH
ARG TG_VERSION=1.2.2
ARG TG_SHA256_amd64=1ba4ad11cf6ac277e8ba59a3fdceb8576778e22f6a24bedd542e91bad9f36491
ARG TG_SHA256_arm64=a730c7daf2fb7dd13e6e7b016b3a89fd4f546bc81a31f8ff19474866c566b755

RUN apk add --no-cache ca-certificates git curl
COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu
RUN set -eu; \
    url="https://github.com/gruntwork-io/terragrunt/releases/download/v${TG_VERSION}/terragrunt_linux_${TARGETARCH}"; \
    curl -fsSL -o /usr/local/bin/terragrunt "$url"; \
    eval "sum=\$TG_SHA256_${TARGETARCH}"; \
    echo "${sum}  /usr/local/bin/terragrunt" | sha256sum -c -; \
    chmod +x /usr/local/bin/terragrunt

ENV TG_TF_PATH=tofu \
    TF_PLUGIN_CACHE_DIR=/plugin-cache
RUN mkdir -p /plugin-cache
WORKDIR /work
