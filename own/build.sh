#!/usr/bin/env bash
# Сборка Bogestv0-Unblock-Setup.exe (нужен Go 1.21+). Запускать из корня репозитория.
set -e
cd "$(dirname "$0")"
VERSION="${VERSION:-2.4.0}"   # в релизе берётся из тега (v2.3.1 → 2.3.1)
REPO="${REPO:-}"            # владелец/репозиторий — для проверки обновлений (в Actions подставляется сам)
(cd app && go test ./... )
rm -rf installer/assets && mkdir -p installer/assets dist
cp NOTICE.txt installer/assets/
cp app/icon.ico installer/assets/Bogestv0-Unblock.ico
(cd app && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$VERSION -X main.ghRepo=$REPO" -o ../installer/assets/Bogestv0-Unblock.exe .)
(cd installer && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o ../dist/Bogestv0-Unblock-Setup.exe .)
ls -la dist/
