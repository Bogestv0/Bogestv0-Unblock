#!/usr/bin/env bash
# Сборка Bogestv0-Unblock-Setup.exe (нужен Go 1.21+). Запускать из корня репозитория.
set -e
cd "$(dirname "$0")"
(cd app && go test ./... )
rm -rf installer/assets && mkdir -p installer/assets dist
cp NOTICE.txt installer/assets/
cp app/icon.ico installer/assets/Bogestv0-Unblock.ico
(cd app && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o ../installer/assets/Bogestv0-Unblock.exe .)
(cd installer && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/Bogestv0-Unblock-Setup.exe .)
ls -la dist/
