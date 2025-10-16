#!/bin/bash

TARGET_URL=${1:-http://localhost:8624/search?query=test}

echo "[*] Starting sqlmap scan on $TARGET_URL ..."

sqlmap -u "$TARGET_URL" --batch --level=3 --risk=2 --random-agent --threads=5 --output-dir=./sqlmap_output

echo "[*] sqlmap scan finished. Check ./sqlmap_output for results."