#!/bin/bash
# tcp-monitor.sh - TCP Connection Monitor for Mining Pool
# Usage: ./tcp-monitor.sh [options]

# Use less strict error handling to avoid silent exits
set -eo pipefail

# Configuration defaults
POOL_PORT="${POOL_PORT:-3333}"
LOG_FILE="${LOG_FILE:-./tcp-monitor.log}"
UPDATE_INTERVAL="${UPDATE_INTERVAL:-2}"
ALERT_THRESHOLD="${ALERT_THRESHOLD:-80}"
QUIET_MODE=false
SHOW_HELP=false

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for tracking
PREVIOUS_PORT_CONNECTIONS=0
MONITOR_START_TIME=$(date +%s)

# Initialize all metrics to 0
PORT_TOTAL=0
PORT_ESTABLISHED=0
PORT_TIME_WAIT=0
PORT_SYN_RECV=0
PORT_OTHER=0
TOTAL_TCP=0
ESTABLISHED=0
TIME_WAIT=0
SYN_SENT=0
SYN_RECV=0
FIN_WAIT1=0
FIN_WAIT2=0
CLOSE_WAIT=0
CLOSING=0
LAST_ACK=0
FD_USED=0
FD_MAX=0
SYN_BACKLOG_USED=0
SYN_BACKLOG_MAX=0
ORPHANS_USED=0
ORPHANS_MAX=0
TW_BUCKETS_USED=0
TW_BUCKETS_MAX=0

# Signal handling for clean exit
cleanup() {
    echo ""
    echo "Stopping TCP monitor..."
    exit 0
}
trap cleanup SIGINT SIGTERM

# Usage information
show_usage() {
    cat << EOF
TCP Connection Monitor for Mining Pool

Usage: $0 [OPTIONS]

OPTIONS:
    -p, --port PORT          Mining pool port to monitor (default: 3333)
    -l, --log FILE          Log file path (default: ./tcp-monitor.log)
    -i, --interval SECONDS  Update interval (default: 2)
    -t, --threshold PERCENT Alert threshold percentage (default: 80)
    -q, --quiet             Quiet mode - log only, no display
    -h, --help              Show this help message

EXAMPLES:
    # Basic usage
    sudo $0

    # Custom port and log file
    sudo $0 -p 3333 -l /var/log/mining-tcp.log

    # Fast updates (every 1 second)
    sudo $0 -i 1

    # Background logging only
    sudo $0 --quiet &

NOTES:
    - Root/sudo access required to read some /proc files
    - Press Ctrl+C to stop monitoring
    - Log file format: CSV with timestamp and metrics

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)
                POOL_PORT="$2"
                shift 2
                ;;
            -l|--log)
                LOG_FILE="$2"
                shift 2
                ;;
            -i|--interval)
                UPDATE_INTERVAL="$2"
                shift 2
                ;;
            -t|--threshold)
                ALERT_THRESHOLD="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                show_usage
                ;;
            *)
                echo "Error: Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Check for required tools
check_requirements() {
    local missing_tools=()

    if ! command -v ss &> /dev/null && ! command -v netstat &> /dev/null; then
        missing_tools+=("ss or netstat")
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Error: Missing required tools: ${missing_tools[*]}"
        echo "Please install the required packages."
        exit 1
    fi
}

# Format number with thousand separators
format_number() {
    printf "%'d" "$1" 2>/dev/null || echo "$1"
}

# Safely convert to integer (handles whitespace, newlines, non-numeric values)
to_int() {
    local val="${1:-0}"
    # Use awk NR==1 to only process first line, handle whitespace and return 0 for invalid input
    if [ -z "$val" ]; then
        echo "0"
        return
    fi
    echo "$val" | awk 'NR==1{print int($1); exit}' || echo "0"
}

# Get TCP connection statistics using ss (preferred) or netstat
get_tcp_stats() {
    local stats_output

    if command -v ss &> /dev/null; then
        stats_output=$(ss -tan 2>/dev/null || echo "")
    else
        stats_output=$(netstat -tan 2>/dev/null || echo "")
    fi

    # Count total TCP connections
    TOTAL_TCP=$(to_int "$(echo "$stats_output" | grep -c "^tcp" 2>/dev/null || echo "0")")

    # Count by state
    ESTABLISHED=$(to_int "$(echo "$stats_output" | grep -c "ESTAB" 2>/dev/null || echo "0")")
    TIME_WAIT=$(to_int "$(echo "$stats_output" | grep -c "TIME-WAIT\|TIME_WAIT" 2>/dev/null || echo "0")")
    SYN_SENT=$(to_int "$(echo "$stats_output" | grep -c "SYN-SENT\|SYN_SENT" 2>/dev/null || echo "0")")
    SYN_RECV=$(to_int "$(echo "$stats_output" | grep -c "SYN-RECV\|SYN_RECV" 2>/dev/null || echo "0")")
    FIN_WAIT1=$(to_int "$(echo "$stats_output" | grep -c "FIN-WAIT-1\|FIN_WAIT1" 2>/dev/null || echo "0")")
    FIN_WAIT2=$(to_int "$(echo "$stats_output" | grep -c "FIN-WAIT-2\|FIN_WAIT2" 2>/dev/null || echo "0")")
    CLOSE_WAIT=$(to_int "$(echo "$stats_output" | grep -c "CLOSE-WAIT\|CLOSE_WAIT" 2>/dev/null || echo "0")")
    CLOSING=$(to_int "$(echo "$stats_output" | grep -c "CLOSING" 2>/dev/null || echo "0")")
    LAST_ACK=$(to_int "$(echo "$stats_output" | grep -c "LAST-ACK\|LAST_ACK" 2>/dev/null || echo "0")")
}

# Get port-specific statistics
get_port_stats() {
    # Note: Variables set here are global and will be used by other functions

    local port_output

    if command -v ss &> /dev/null; then
        port_output=$(ss -tan 2>/dev/null | grep ":${POOL_PORT}" || echo "")
    else
        port_output=$(netstat -tan 2>/dev/null | grep ":${POOL_PORT}" || echo "")
    fi

    # Total connections on the port (strip whitespace with xargs, default to 0)
    PORT_TOTAL=$(echo "$port_output" | grep -c "^tcp" 2>/dev/null | xargs)
    PORT_TOTAL=${PORT_TOTAL:-0}

    # By state
    PORT_ESTABLISHED=$(echo "$port_output" | grep -c "ESTAB" 2>/dev/null | xargs)
    PORT_ESTABLISHED=${PORT_ESTABLISHED:-0}

    PORT_TIME_WAIT=$(echo "$port_output" | grep -c "TIME-WAIT\|TIME_WAIT" 2>/dev/null | xargs)
    PORT_TIME_WAIT=${PORT_TIME_WAIT:-0}

    PORT_SYN_RECV=$(echo "$port_output" | grep -c "SYN-RECV\|SYN_RECV" 2>/dev/null | xargs)
    PORT_SYN_RECV=${PORT_SYN_RECV:-0}

    # Calculate PORT_OTHER, ensuring it's not negative
    local calc=$((PORT_TOTAL - PORT_ESTABLISHED - PORT_TIME_WAIT - PORT_SYN_RECV))
    if [ $calc -lt 0 ] 2>/dev/null; then
        PORT_OTHER=0
    else
        PORT_OTHER=$calc
    fi

    # Check for sudden drops (ensure variables are numeric)
    local prev_conn=$(to_int "$PREVIOUS_PORT_CONNECTIONS")
    local curr_conn=$(to_int "$PORT_TOTAL")

    if [ "$prev_conn" -gt 0 ] 2>/dev/null; then
        if [ "$curr_conn" -lt "$prev_conn" ] 2>/dev/null; then
            local drop_percent=$(awk "BEGIN {print int(($prev_conn - $curr_conn) * 100 / $prev_conn)}")
            if [ "$drop_percent" -gt 10 ] 2>/dev/null; then
                WARNINGS+=("Sudden connection drop detected: ${drop_percent}% decrease")
            fi
        fi
    fi

    PREVIOUS_PORT_CONNECTIONS=$PORT_TOTAL
}

# Get system limits from /proc
get_system_limits() {
    # File descriptors
    if [ -r /proc/sys/fs/file-max ]; then
        FD_MAX=$(to_int "$(cat /proc/sys/fs/file-max 2>/dev/null || echo "0")")
    else
        FD_MAX=0
    fi

    if [ -r /proc/sys/fs/file-nr ]; then
        # Format: allocated unused max
        FD_USED=$(to_int "$(awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null || echo "0")")
    else
        FD_USED=0
    fi

    # TCP SYN backlog
    if [ -r /proc/sys/net/ipv4/tcp_max_syn_backlog ]; then
        SYN_BACKLOG_MAX=$(to_int "$(cat /proc/sys/net/ipv4/tcp_max_syn_backlog 2>/dev/null || echo "0")")
    else
        SYN_BACKLOG_MAX=0
    fi

    # Approximate SYN backlog usage (using SYN_RECV count)
    SYN_BACKLOG_USED=$(to_int "$SYN_RECV")

    # TCP orphans
    if [ -r /proc/sys/net/ipv4/tcp_max_orphans ]; then
        ORPHANS_MAX=$(to_int "$(cat /proc/sys/net/ipv4/tcp_max_orphans 2>/dev/null || echo "0")")
    else
        ORPHANS_MAX=0
    fi

    # Get current orphans count
    if [ -r /proc/net/sockstat ]; then
        ORPHANS_USED=$(to_int "$(grep "TCP:" /proc/net/sockstat 2>/dev/null | awk '{print $5}' || echo "0")")
    else
        ORPHANS_USED=0
    fi

    # TIME_WAIT buckets
    if [ -r /proc/sys/net/ipv4/tcp_max_tw_buckets ]; then
        TW_BUCKETS_MAX=$(to_int "$(cat /proc/sys/net/ipv4/tcp_max_tw_buckets 2>/dev/null || echo "0")")
    else
        TW_BUCKETS_MAX=0
    fi

    TW_BUCKETS_USED=$(to_int "$TIME_WAIT")
}

# Check thresholds and generate warnings
check_thresholds() {
    WARNINGS=()

    # File descriptors (use awk for large numbers)
    if [ -n "$FD_MAX" ] && [ "$FD_MAX" != "0" ]; then
        local fd_percent=$(awk "BEGIN {print int($FD_USED * 100 / $FD_MAX)}")
        if [ "$fd_percent" -ge "$ALERT_THRESHOLD" ] 2>/dev/null; then
            WARNINGS+=("File Descriptors at ${fd_percent}%")
        fi
    fi

    # SYN backlog
    if [ -n "$SYN_BACKLOG_MAX" ] && [ "$SYN_BACKLOG_MAX" != "0" ]; then
        local syn_percent=$(awk "BEGIN {print int($SYN_BACKLOG_USED * 100 / $SYN_BACKLOG_MAX)}")
        if [ "$syn_percent" -ge 75 ] 2>/dev/null; then
            WARNINGS+=("SYN Backlog at ${syn_percent}%")
        fi
    fi

    # Orphans
    if [ -n "$ORPHANS_MAX" ] && [ "$ORPHANS_MAX" != "0" ]; then
        local orphans_percent=$(awk "BEGIN {print int($ORPHANS_USED * 100 / $ORPHANS_MAX)}")
        if [ "$orphans_percent" -ge 75 ] 2>/dev/null; then
            WARNINGS+=("TCP Orphans at ${orphans_percent}%")
        fi
    fi

    # TIME_WAIT buckets
    if [ -n "$TW_BUCKETS_MAX" ] && [ "$TW_BUCKETS_MAX" != "0" ]; then
        local tw_percent=$(awk "BEGIN {print int($TW_BUCKETS_USED * 100 / $TW_BUCKETS_MAX)}")
        if [ "$tw_percent" -ge "$ALERT_THRESHOLD" ] 2>/dev/null; then
            WARNINGS+=("TIME_WAIT Buckets at ${tw_percent}%")
        fi
    fi
}

# Get status indicator (color + symbol)
get_status_indicator() {
    local used=$1
    local max=$2

    # Handle zero or empty max
    if [ -z "$max" ] || [ "$max" = "0" ]; then
        echo "${BLUE}N/A${NC}"
        return
    fi

    # Use awk for percentage calculation to handle large numbers
    local percent=$(awk "BEGIN {print int($used * 100 / $max)}")

    if [ "$percent" -ge "$ALERT_THRESHOLD" ] 2>/dev/null; then
        echo "${RED}✗ CRITICAL${NC}"
    elif [ "$percent" -ge 75 ] 2>/dev/null; then
        echo "${YELLOW}⚠ WARNING${NC}"
    else
        echo "${GREEN}✓ OK${NC}"
    fi
}

# Display real-time statistics
display_stats() {
    if [ "$QUIET_MODE" = true ]; then
        return
    fi

    clear

    local runtime=$(($(date +%s) - MONITOR_START_TIME))
    local runtime_fmt=$(printf "%02d:%02d:%02d" $((runtime/3600)) $((runtime%3600/60)) $((runtime%60)))

    echo "=========================================="
    echo "TCP Connection Monitor - Mining Pool"
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Runtime: $runtime_fmt"
    echo "=========================================="
    echo ""

    echo -e "${BLUE}PORT $POOL_PORT CONNECTIONS:${NC}"
    echo "  Total: $(format_number $PORT_TOTAL) connections"
    echo "  ESTABLISHED: $(format_number $PORT_ESTABLISHED)"
    echo "  TIME_WAIT: $(format_number $PORT_TIME_WAIT)"
    echo "  SYN_RECV: $(format_number $PORT_SYN_RECV)"
    echo "  Other: $(format_number $PORT_OTHER)"
    echo ""

    echo -e "${BLUE}ALL TCP CONNECTIONS:${NC}"
    echo "  Total: $(format_number $TOTAL_TCP)"
    echo "  By State:"
    echo "    ESTABLISHED: $(format_number $ESTABLISHED)"
    echo "    TIME_WAIT: $(format_number $TIME_WAIT)"
    echo "    SYN_RECV: $(format_number $SYN_RECV)"
    echo "    SYN_SENT: $(format_number $SYN_SENT)"
    echo "    FIN_WAIT: $(format_number $((FIN_WAIT1 + FIN_WAIT2)))"
    echo "    CLOSE_WAIT: $(format_number $CLOSE_WAIT)"
    echo "    CLOSING: $(format_number $CLOSING)"
    echo "    LAST_ACK: $(format_number $LAST_ACK)"
    echo ""

    echo -e "${BLUE}SYSTEM LIMITS STATUS:${NC}"

    # File descriptors (use awk for large number comparison)
    if [ -n "$FD_MAX" ] && [ "$FD_MAX" != "0" ]; then
        local fd_percent=$(awk "BEGIN {printf \"%.1f\", ($FD_USED * 100.0 / $FD_MAX)}")
        echo -e "  File Descriptors: $(format_number $FD_USED) / $(format_number $FD_MAX) (${fd_percent}%) $(get_status_indicator $FD_USED $FD_MAX)"
    fi

    # SYN backlog
    if [ -n "$SYN_BACKLOG_MAX" ] && [ "$SYN_BACKLOG_MAX" != "0" ]; then
        local syn_percent=$(awk "BEGIN {printf \"%.1f\", ($SYN_BACKLOG_USED * 100.0 / $SYN_BACKLOG_MAX)}")
        echo -e "  TCP SYN Backlog: $(format_number $SYN_BACKLOG_USED) / $(format_number $SYN_BACKLOG_MAX) (${syn_percent}%) $(get_status_indicator $SYN_BACKLOG_USED $SYN_BACKLOG_MAX)"
    fi

    # TCP orphans
    if [ -n "$ORPHANS_MAX" ] && [ "$ORPHANS_MAX" != "0" ]; then
        local orphans_percent=$(awk "BEGIN {printf \"%.1f\", ($ORPHANS_USED * 100.0 / $ORPHANS_MAX)}")
        echo -e "  TCP Orphans: $(format_number $ORPHANS_USED) / $(format_number $ORPHANS_MAX) (${orphans_percent}%) $(get_status_indicator $ORPHANS_USED $ORPHANS_MAX)"
    fi

    # TIME_WAIT buckets
    if [ -n "$TW_BUCKETS_MAX" ] && [ "$TW_BUCKETS_MAX" != "0" ]; then
        local tw_percent=$(awk "BEGIN {printf \"%.1f\", ($TW_BUCKETS_USED * 100.0 / $TW_BUCKETS_MAX)}")
        echo -e "  TIME_WAIT Buckets: $(format_number $TW_BUCKETS_USED) / $(format_number $TW_BUCKETS_MAX) (${tw_percent}%) $(get_status_indicator $TW_BUCKETS_USED $TW_BUCKETS_MAX)"
    fi

    echo ""

    # Display warnings
    if [ ${#WARNINGS[@]} -eq 0 ]; then
        echo -e "${GREEN}⚠ WARNINGS: None${NC}"
    else
        echo -e "${RED}⚠ WARNINGS:${NC}"
        for warning in "${WARNINGS[@]}"; do
            echo -e "  ${RED}• $warning${NC}"
        done
    fi

    echo ""
    echo "[Press Ctrl+C to stop]"
}

# Log statistics to CSV file
log_stats() {
    local timestamp=$(date '+%Y-%m-%dT%H:%M:%S')

    # Create log file with header if it doesn't exist
    if [ ! -f "$LOG_FILE" ]; then
        echo "timestamp,port_total,port_established,port_timewait,port_synrecv,port_other,total_tcp,established,timewait,synrecv,fd_used,fd_max,syn_backlog_used,syn_backlog_max,orphans_used,orphans_max,tw_buckets_used,tw_buckets_max,warnings" > "$LOG_FILE"
    fi

    # Build warnings string
    local warnings_str=""
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        warnings_str=$(IFS=';'; echo "${WARNINGS[*]}")
    fi

    # Append data
    echo "$timestamp,$PORT_TOTAL,$PORT_ESTABLISHED,$PORT_TIME_WAIT,$PORT_SYN_RECV,$PORT_OTHER,$TOTAL_TCP,$ESTABLISHED,$TIME_WAIT,$SYN_RECV,$FD_USED,$FD_MAX,$SYN_BACKLOG_USED,$SYN_BACKLOG_MAX,$ORPHANS_USED,$ORPHANS_MAX,$TW_BUCKETS_USED,$TW_BUCKETS_MAX,\"$warnings_str\"" >> "$LOG_FILE"
}

# Main monitoring loop
main_loop() {
    while true; do
        # Collect all metrics (with error handling)
        if ! get_tcp_stats; then
            echo "Warning: Failed to get TCP stats" >&2
        fi

        if ! get_port_stats; then
            echo "Warning: Failed to get port stats" >&2
        fi

        if ! get_system_limits; then
            echo "Warning: Failed to get system limits" >&2
        fi

        check_thresholds

        # Display and log
        display_stats
        log_stats

        # Wait for next interval
        sleep "$UPDATE_INTERVAL"
    done
}

# Main execution
main() {
    parse_args "$@"

    # Show startup message
    if [ "$QUIET_MODE" = false ]; then
        echo "Starting TCP Connection Monitor..."
        echo "Port: $POOL_PORT"
        echo "Log: $LOG_FILE"
        echo "Update interval: ${UPDATE_INTERVAL}s"
        echo "Alert threshold: ${ALERT_THRESHOLD}%"
        echo ""
        sleep 1
    fi

    check_requirements

    # Test metrics collection before starting loop
    if [ "$QUIET_MODE" = false ]; then
        echo "Testing metrics collection..."
    fi

    if ! get_tcp_stats 2>/dev/null; then
        echo "Warning: Could not collect TCP stats. Continuing anyway..." >&2
    fi

    if ! get_port_stats 2>/dev/null; then
        echo "Warning: Could not collect port stats. Continuing anyway..." >&2
    fi

    if ! get_system_limits 2>/dev/null; then
        echo "Warning: Could not collect system limits. Continuing anyway..." >&2
    fi

    if [ "$QUIET_MODE" = false ]; then
        echo "Metrics collection test complete. Starting monitor..."
        echo ""
        sleep 1
    fi

    main_loop
}

# Run main function with all arguments
main "$@"