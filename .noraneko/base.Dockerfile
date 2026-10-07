# syntax=docker/dockerfile:1
# artex 런타임 base 이미지(D-024). 무거운 arm64 레이어(apt recon 도구 + Node 20 +
# Playwright/Chromium)만 담는다. OCI 빌드 러너는 x86_64 고정이고 arm64 RUN 을 에뮬레이션하지
# 못하므로(binfmt_misc 마운트 불가), 이 이미지는 operator 가 arm64 맥에서 네이티브로 1회 빌드해
# OCIR noraneko/artex-base 로 올린다. 앱 이미지(.noraneko/Dockerfile)는 이걸 FROM 해 COPY 만 한다.
# npm 전역 패키지는 재현성을 위해 정확한 버전으로 고정한다(@latest 금지).
FROM python:3.12-slim-bookworm
# 상용 도구 + recon 상비 도구. Node 는 NodeSource 20.x(bookworm apt nodejs 는 18, Playwright 는 >=20).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Playwright MCP/CLI/런타임 전역 설치 + Chromium·시스템 의존성 사전 설치(런타임 네트워크 다운로드 제거).
RUN npm install -g @playwright/mcp@0.0.83 @playwright/cli@0.1.22 playwright@1.63.0 \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
