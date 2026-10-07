# syntax=docker/dockerfile:1
# artex 앱 이미지(D-024). base 는 operator 가 네이티브 arm64 로 빌드해 올린 noraneko/artex-base.
# 여기엔 RUN 이 하나도 없다 — x86 러너에서 에뮬레이션 없이 COPY 만 하므로 빌드된다(oshilog 패턴).
# base digest 는 operator 가 base push 후 아래 PLACEHOLDER 를 실제 sha256 으로 바꾼다.
FROM --platform=linux/arm64 yny.ocir.io/axbhyh1fdkqm/noraneko/artex-base@sha256:PLACEHOLDER
WORKDIR /app
COPY --chmod=0755 dist/arm64/artex /app/artex
COPY --chmod=0755 start.sh /app/start.sh
COPY skills/ /app/skills/
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
