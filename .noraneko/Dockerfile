# syntax=docker/dockerfile:1
# artex 앱 이미지(D-024). base 는 operator 가 네이티브 arm64 로 빌드해 올린 noraneko/artex-base.
# 여기엔 RUN 이 하나도 없다 — x86 러너에서 에뮬레이션 없이 COPY 만 하므로 빌드된다(oshilog 패턴).
# FROM digest 는 noraneko/artex-base(public, D-024)의 실제 sha256. base 를 다시 빌드·push 하면 이 digest 를 바꾼다.
FROM --platform=linux/arm64 yny.ocir.io/axbhyh1fdkqm/noraneko/artex-base@sha256:30ef519b15833a6daabd45efd621a05910ddbcda8d01d9af98fb55e12c21f523
WORKDIR /app
COPY --chmod=0755 dist/arm64/artex /app/artex
COPY --chmod=0755 start.sh /app/start.sh
COPY skills/ /app/skills/
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
