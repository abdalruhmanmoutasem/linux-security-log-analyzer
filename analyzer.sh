if [ -z "$1" ]; then
    echo "Usage: ./analyzer.sh <log_file>"
    exit 1
fi

LOG_FILE="$1"
THRESHOLD=3
if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file not found: $LOG_FILE"
    exit 1
fi

echo "Analyzing: $LOG_FILE"
echo

SUCCESSFUL_LOGINS=$(grep "Successful login" "$LOG_FILE" | wc -l)
FAILED_LOGINS=$(grep "Failed login" "$LOG_FILE" | wc -l)

echo "Successful login attempts: $SUCCESSFUL_LOGINS"
echo "Failed login attempts: $FAILED_LOGINS"
echo

echo "Failed attempts by IP:"
grep "Failed login" "$LOG_FILE" | awk '{print $NF}' | sort | uniq -c

echo
echo "Suspicious IPs:"
grep "Failed login" "$LOG_FILE" | awk '{print $NF}' | sort | uniq -c | awk -v threshold="$THRESHOLD" '$1 >= threshold {print "IP:", $2, "| Failed attempts:", $1}'
