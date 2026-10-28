#!/usr/bin/env bash
# web/public/icon.svg から PWA 用の PNG アイコンを作る。
set -euo pipefail
SRC="${1:-web/public/icon.svg}"
OUT="${2:-web/public/icons}"
mkdir -p "$OUT"
rsvg-convert -w 192 -h 192 "$SRC" -o "$OUT/icon-192.png"
rsvg-convert -w 512 -h 512 "$SRC" -o "$OUT/icon-512.png"
