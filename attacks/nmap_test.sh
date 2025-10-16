TARGET=${1:-localhost}   # Default target localhost
PORT=${2:-$(docker port aass_web_honeypot 80 | sed 's/.*://')}  # Get mapped port or default

echo "[*] Starting Nmap scan on $TARGET:$PORT ..."
nmap -sV -sC -p $PORT $TARGET --script=http-vuln* -oN nmap_scan_results.txt

echo "[*] Nmap scan finished. See nmap_scan_results.txt"
cat nmap_scan_results.txt