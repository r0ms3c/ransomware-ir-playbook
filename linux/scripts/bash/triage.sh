#!/usr/bin/env bash
# =============================================================================
# triage.sh — Ransomware First-Response Triage
# =============================================================================
# Purpose : Capture volatile system data from a suspected ransomware host
#           before it is lost to isolation or reboot.
# Author  : r0ms3c
# Usage   : sudo ./triage.sh [--output /path/to/evidence] [--quiet]
# Requires: root privileges
# =============================================================================

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
OUTPUT_DIR="/tmp/ir-triage-$(hostname)-$(date +%Y%m%d_%H%M%S)"
QUIET=false
SCRIPT_VERSION="1.0.0"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --output|-o) OUTPUT_DIR="$2"; shift 2 ;;
    --quiet|-q)  QUIET=true; shift ;;
    --help|-h)
      echo "Usage: sudo $0 [--output /path] [--quiet]"
      echo "  --output DIR   Where to write evidence (default: /tmp/ir-triage-HOSTNAME-TIMESTAMP)"
      echo "  --quiet        Suppress progress output"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Helper Functions ──────────────────────────────────────────────────────────
log()  { $QUIET || echo -e "${CYAN}[*]${NC} $*"; }
ok()   { $QUIET || echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
fail() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

run_and_save() {
  local label="$1"; local outfile="$2"; shift 2
  log "Collecting: $label"
  echo "### $label — $(date -u '+%Y-%m-%dT%H:%M:%SZ') ###" >> "$outfile"
  "$@" >> "$outfile" 2>&1 || warn "Command failed: $*"
  echo "" >> "$outfile"
}

# ── Privilege Check ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Must run as root. Use: sudo $0"

# ── Setup ─────────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"/{volatile,network,processes,filesystem,auth,scheduled,kernel}
SUMMARY="$OUTPUT_DIR/TRIAGE_SUMMARY.txt"
START_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║    RANSOMWARE IR — HOST TRIAGE COLLECTION            ║"
echo "║    Version: $SCRIPT_VERSION                                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

cat > "$SUMMARY" <<EOF
=============================================================
  RANSOMWARE IR TRIAGE REPORT
  Host    : $(hostname -f)
  Started : $START_TIME
  By User : $(who am i 2>/dev/null || echo "root")
  Script  : $SCRIPT_VERSION
=============================================================

EOF

log "Output directory: $OUTPUT_DIR"

# ── 1. SYSTEM IDENTITY ────────────────────────────────────────────────────────
log "━━━ Phase 1: System Identity ━━━"
SYS="$OUTPUT_DIR/volatile/system_info.txt"
run_and_save "Hostname & Date"    "$SYS" bash -c 'echo "Hostname: $(hostname -f)"; echo "Date: $(date -u)"; echo "Uptime: $(uptime)"'
run_and_save "Kernel & OS"        "$SYS" bash -c 'uname -a; cat /etc/os-release'
run_and_save "Logged-in Users"    "$SYS" bash -c 'who; echo "---"; w'
run_and_save "Last Logins"        "$SYS" last -n 50
run_and_save "Failed Logins"      "$SYS" lastb -n 50 2>/dev/null || true
run_and_save "Environment Vars"   "$SYS" env

# ── 2. PROCESS SNAPSHOT ───────────────────────────────────────────────────────
log "━━━ Phase 2: Running Processes ━━━"
PROC="$OUTPUT_DIR/processes/processes.txt"
run_and_save "Full Process Tree"  "$PROC" ps auxef
run_and_save "Process Tree (pstree)" "$PROC" pstree -aup 2>/dev/null || true
run_and_save "Top CPU Consumers"  "$PROC" bash -c 'ps aux --sort=-%cpu | head -30'
run_and_save "Top MEM Consumers"  "$PROC" bash -c 'ps aux --sort=-%mem | head -30'
run_and_save "Open Files (lsof)"  "$PROC" lsof 2>/dev/null | head -500 || true

# Map process executables — look for deleted/unusual binaries
log "Mapping process executables..."
EXEC_MAP="$OUTPUT_DIR/processes/process_executables.txt"
echo "### Process → Executable Map ###" > "$EXEC_MAP"
for pid in /proc/[0-9]*/exe; do
  target=$(readlink "$pid" 2>/dev/null) || continue
  ppid=$(basename "$(dirname "$pid")")
  echo "PID $ppid → $target" >> "$EXEC_MAP"
done
grep -i "deleted\|memfd\|/tmp\|/dev/shm" "$EXEC_MAP" >> "$OUTPUT_DIR/processes/SUSPICIOUS_PROCESSES.txt" 2>/dev/null || true

# ── 3. NETWORK STATE ──────────────────────────────────────────────────────────
log "━━━ Phase 3: Network State ━━━"
NET="$OUTPUT_DIR/network/network_state.txt"
run_and_save "Listening Ports (ss)"   "$NET" ss -tulnp
run_and_save "All Connections"        "$NET" ss -anp
run_and_save "Established (netstat)"  "$NET" netstat -antp 2>/dev/null || true
run_and_save "Routing Table"          "$NET" ip route show
run_and_save "ARP Table"              "$NET" ip neigh show
run_and_save "Network Interfaces"     "$NET" ip addr show
run_and_save "iptables Rules"         "$NET" iptables -L -n -v 2>/dev/null || true
run_and_save "DNS Config"             "$NET" bash -c 'cat /etc/resolv.conf; cat /etc/hosts'
run_and_save "Recent DNS (systemd)"   "$NET" systemd-resolve --statistics 2>/dev/null || true

# ── 4. AUTHENTICATION LOGS ────────────────────────────────────────────────────
log "━━━ Phase 4: Authentication History ━━━"
AUTH="$OUTPUT_DIR/auth/auth_events.txt"
run_and_save "Auth Log (last 500)"    "$AUTH" bash -c 'tail -500 /var/log/auth.log 2>/dev/null || journalctl _COMM=sshd -n 500 --no-pager'
run_and_save "SSH Accepted Logins"    "$AUTH" bash -c 'grep "Accepted" /var/log/auth.log 2>/dev/null | tail -100 || true'
run_and_save "SSH Failed Logins"      "$AUTH" bash -c 'grep "Failed\|Invalid\|error" /var/log/auth.log 2>/dev/null | tail -100 || true'
run_and_save "Sudo Events"            "$AUTH" bash -c 'grep "sudo\|COMMAND" /var/log/auth.log 2>/dev/null | tail -100 || true'

# Privileged accounts check
echo "### Root-equivalent Accounts ###" >> "$AUTH"
awk -F: '$3==0{print "UID 0 account: "$1}' /etc/passwd >> "$AUTH"
echo "" >> "$AUTH"
echo "### Sudo Group Members ###" >> "$AUTH"
getent group sudo wheel 2>/dev/null >> "$AUTH" || true

# ── 5. FILESYSTEM INDICATORS ──────────────────────────────────────────────────
log "━━━ Phase 5: Filesystem Indicators ━━━"
FS="$OUTPUT_DIR/filesystem/filesystem_iocs.txt"

log "Scanning for ransom notes..."
echo "### Ransom Note Search ###" > "$FS"
find / -xdev -type f \( \
  -iname "*readme*" -o -iname "*decrypt*" -o -iname "*ransom*" -o \
  -iname "*recover*files*" -o -iname "*how_to*" -o -iname "*pay*btc*" \
\) 2>/dev/null | tee -a "$FS"

log "Scanning for encrypted file extensions..."
echo "" >> "$FS"
echo "### Suspicious File Extensions ###" >> "$FS"
find / -xdev -type f -regextype posix-extended \
  -regex '.*\.(locked|enc|crypt|pay|ransom|encrypted|crypted|encoded)$' \
  2>/dev/null | head -200 | tee -a "$FS"

log "Checking recently modified files (last 60 min)..."
echo "" >> "$FS"
echo "### Recently Modified Files (60 min) ###" >> "$FS"
find /home /var /opt /srv /data /root -xdev -mmin -60 -type f 2>/dev/null | \
  head -300 >> "$FS" || true

# Mounted filesystems
run_and_save "Mounted Filesystems"  "$FS" bash -c 'mount | column -t; echo "---"; df -h'

# ── 6. SCHEDULED TASKS ───────────────────────────────────────────────────────
log "━━━ Phase 6: Persistence Mechanisms ━━━"
SCHED="$OUTPUT_DIR/scheduled/scheduled_tasks.txt"
run_and_save "Root Crontab"           "$SCHED" bash -c 'crontab -l 2>/dev/null || echo "No root crontab"'
run_and_save "System Crontab"         "$SCHED" cat /etc/crontab
run_and_save "Cron.d Contents"        "$SCHED" bash -c 'ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null || true'
run_and_save "All User Crontabs"      "$SCHED" bash -c 'for u in $(cut -f1 -d: /etc/passwd); do echo "==$u=="; crontab -u $u -l 2>/dev/null || true; done'
run_and_save "Systemd Units (running)""$SCHED" systemctl list-units --type=service --state=running --no-pager
run_and_save "Systemd Units (all)"    "$SCHED" systemctl list-units --type=service --no-pager
run_and_save "rc.local"               "$SCHED" bash -c 'cat /etc/rc.local 2>/dev/null || echo "Not found"'
run_and_save "SSH authorized_keys"    "$SCHED" bash -c 'find / -name "authorized_keys" -exec echo "FILE: {}" \; -exec cat {} \; 2>/dev/null || true'

# ── 7. KERNEL & MODULES ───────────────────────────────────────────────────────
log "━━━ Phase 7: Kernel & Modules ━━━"
KERN="$OUTPUT_DIR/kernel/kernel_state.txt"
run_and_save "Loaded Kernel Modules"  "$KERN" lsmod
run_and_save "ld.so.preload"          "$KERN" bash -c 'cat /etc/ld.so.preload 2>/dev/null || echo "Empty/not found"'
run_and_save "Shared Lib Paths"       "$KERN" ldconfig -p | head -50
run_and_save "AppArmor Status"        "$KERN" bash -c 'aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo "AppArmor not available"'
run_and_save "SELinux Status"         "$KERN" bash -c 'sestatus 2>/dev/null || echo "SELinux not available"'

# ── 8. GENERATE CHECKSUMS ─────────────────────────────────────────────────────
log "━━━ Phase 8: Checksums & Chain of Custody ━━━"
find "$OUTPUT_DIR" -type f ! -name "*.sha256" | sort | \
  xargs sha256sum 2>/dev/null > "$OUTPUT_DIR/CHAIN_OF_CUSTODY.sha256"

# ── 9. SUMMARY REPORT ─────────────────────────────────────────────────────────
END_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
RANSOM_NOTES=$(grep -c "^/" "$OUTPUT_DIR/filesystem/filesystem_iocs.txt" 2>/dev/null || echo 0)
SUSPICIOUS_PROCS=$(wc -l < "$OUTPUT_DIR/processes/SUSPICIOUS_PROCESSES.txt" 2>/dev/null || echo 0)

cat >> "$SUMMARY" <<EOF
COLLECTION COMPLETE
===================
Started  : $START_TIME
Finished : $END_TIME
Output   : $OUTPUT_DIR

FINDINGS SUMMARY
================
Ransom notes found   : $RANSOM_NOTES
Suspicious processes : $SUSPICIOUS_PROCS

NEXT STEPS
==========
1. Review SUSPICIOUS_PROCESSES.txt immediately
2. Review filesystem/filesystem_iocs.txt for encrypted files
3. Run isolate.sh if ransomware is confirmed
4. Run forensic-capture.sh for full memory/disk imaging
5. Copy this evidence directory to isolated storage

CHAIN OF CUSTODY
================
SHA256 checksums: $OUTPUT_DIR/CHAIN_OF_CUSTODY.sha256
Analyst: $(who am i 2>/dev/null | awk '{print $1}' || echo 'root')
EOF

echo ""
echo -e "${BOLD}${GREEN}━━━ TRIAGE COMPLETE ━━━${NC}"
echo -e "${GREEN}Output:${NC} $OUTPUT_DIR"
echo -e "${YELLOW}Ransom notes found:${NC} $RANSOM_NOTES"
echo -e "${YELLOW}Suspicious processes:${NC} $SUSPICIOUS_PROCS"
echo ""
echo -e "${RED}⚠  If ransomware is confirmed, run isolate.sh IMMEDIATELY${NC}"
echo ""
