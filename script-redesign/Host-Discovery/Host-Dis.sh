#!/bin/bash

# ===== Ctrl+C Handling =====
cleanup() {
    echo ""
    echo "[!] Scan interrupted. Stopping all processes..."
    pkill -P $$
    exit 1
}
trap cleanup SIGINT

read -p "Enter Organization Name: " ORG_NAME
ORG_NAME=$(echo "$ORG_NAME" | tr ' ' '_' )

SUBNET="192.168.0"
START_IP=1
END_IP=254

OUTPUT_DIR="./$ORG_NAME"
mkdir -p "$OUTPUT_DIR"

if [ ! -w "$OUTPUT_DIR" ]; then
    echo "[ERROR] No write permission for $OUTPUT_DIR"
    exit 1
fi

CSV_FILE="$OUTPUT_DIR/Host-Discovery.csv"
TXT_FILE="$OUTPUT_DIR/Host-Discovery.txt"
LOG_FILE="$OUTPUT_DIR/Scan.log"

MAX_CONCURRENT=20
PING_TIMEOUT=1
RETRIES=2

echo "Starting scan for $ORG_NAME..." | tee -a "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"

echo "IPAddress,HostName,MAC,Vendor,DeviceType" > "$CSV_FILE"
TMP_FILE=$(mktemp)

classify_device() {
    ip=$1
    vendor=$2

    type="Unknown"

    timeout 1 bash -c "</dev/tcp/$ip/22" &>/dev/null && type="Linux Endpoint"
    timeout 1 bash -c "</dev/tcp/$ip/3389" &>/dev/null && type="Windows Endpoint"
    timeout 1 bash -c "</dev/tcp/$ip/9100" &>/dev/null && type="Printer"
    timeout 1 bash -c "</dev/tcp/$ip/554" &>/dev/null && type="Camera"
    timeout 1 bash -c "</dev/tcp/$ip/80" &>/dev/null && [[ "$type" == "Unknown" ]] && type="Web Device"

    if [[ "$vendor" =~ "Cisco" || "$vendor" =~ "Juniper" ]]; then
        type="Network Device"
    elif [[ "$vendor" =~ "HP" || "$vendor" =~ "Canon" || "$vendor" =~ "Epson" ]]; then
        type="Printer"
    elif [[ "$vendor" =~ "Hikvision" || "$vendor" =~ "Dahua" ]]; then
        type="Camera"
    elif [[ "$vendor" =~ "Dell" || "$vendor" =~ "Lenovo" || "$vendor" =~ "Apple" ]]; then
        [[ "$type" == "Unknown" ]] && type="Endpoint"
    fi

    echo "$type"
}

check_host() {
    ip=$1

    for ((i=1; i<=RETRIES; i++)); do
        if ping -c 1 -W $PING_TIMEOUT $ip > /dev/null 2>&1; then
            
            hostname=$(getent hosts $ip | awk '{print $2}')
            mac=$(ip neigh show $ip | awk '{print $5}')
            vendor="Unknown"

            if [[ -f "/usr/share/nmap/nmap-mac-prefixes" && -n "$mac" ]]; then
                prefix=$(echo $mac | cut -d':' -f1-3 | tr '[:lower:]' '[:upper:]')
                vendor=$(grep "^$prefix" /usr/share/nmap/nmap-mac-prefixes | cut -d' ' -f2-)
            fi

            device_type=$(classify_device "$ip" "$vendor")

            echo "$ip,$hostname,$mac,$vendor,$device_type" >> "$TMP_FILE"
            echo "Discovered: $ip ($device_type)" >> "$LOG_FILE"
            return
        fi
    done
}

for i in $(seq $START_IP $END_IP); do
    ip="$SUBNET.$i"

    check_host "$ip" &

    while (( $(jobs -r | wc -l) >= MAX_CONCURRENT )); do
        sleep 0.2
    done
done

wait

cat "$TMP_FILE" >> "$CSV_FILE"

TOTAL=$(wc -l < "$TMP_FILE")

# ===== TXT REPORT =====
{
echo "========================================="
echo "     NETWORK DISCOVERY REPORT"
echo "========================================="
echo "Organization : $ORG_NAME"
echo "Date         : $(date)"
echo "Subnet       : $SUBNET.0/24"
echo ""

echo "Total Devices Discovered : $TOTAL"
echo ""

echo "========== DEVICE SUMMARY =========="
cut -d',' -f5 "$TMP_FILE" | sort | uniq -c | while read count type; do
    printf "%-20s : %s\n" "$type" "$count"
done

echo ""
echo "========== DEVICE DETAILS =========="
printf "%-15s %-25s %-20s %-25s %-20s\n" "IP Address" "HostName" "MAC" "Vendor" "Device Type"
echo "-----------------------------------------------------------------------------------------------------------"

while IFS=',' read -r ip host mac vendor type; do
    printf "%-15s %-25s %-20s %-25s %-20s\n" "$ip" "$host" "$mac" "$vendor" "$type"
done < "$TMP_FILE"

} > "$TXT_FILE"

rm "$TMP_FILE"

echo ""
echo "Scan complete."
echo "Total Devices: $TOTAL"
