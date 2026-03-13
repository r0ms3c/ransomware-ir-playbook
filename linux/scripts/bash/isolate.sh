#!/usr/bin/env bash
# =============================================================================
# isolate.sh — Network Isolation for Ransomware Containment
# =============================================================================
# Purpose : Isolate a compromised Ubuntu host at the network layer while
#           preserving SSH access for the IR team.
# Author  : r0ms3c
# Usage   : sudo ./isolate.sh --mode firewall --mgmt-ip <IR_JUMPBOX_IP>
# Modes   : firewall (UFW/iptables), vlan (placeholder), full (hard drop all)
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="firewall"
MGMT_IP=""
MGMT_PORT=22
DRY_RUN=false
ROLLBACK=false
BACKUP_FILE="/tmp/iptables-pre-isolation-$(date +%Y%m%d_%H%M%S).rules"
LOG_FILE="/var/log/ir-isolation.log"
SCRIPT_VERSION="1.0.0"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [INFO] $*";  echo -e "${CYAN}[*]${NC} $*"; echo "$msg" >> "$LOG_FILE"; }
ok()   { local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [OK]   $*";  echo -e "${GREEN}[+]${NC} $*"; echo "$msg" >> "$LOG_FILE"; }
warn() { local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [WARN] $*";  echo -e "${YELLOW}[!]${NC} $*" >&2; echo "$msg" >> "$LOG_FILE"; }
fail() { local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [FAIL] $*";  echo -e "${RED}[✗]${NC} $*" >&2; echo "$msg" >> "$LOG_FILE"; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  --mode MODE        Isolation mode: firewall (default), full
  --mgmt-ip IP       IR team jumpbox IP (REQUIRED for firewall mode)
  --mgmt-port PORT   SSH port to keep open (default: 22)
  --dry-run          Show what would be done without applying changes
  --rollback         Remove isolation rules and restore original config
  --help             Show this help

Examples:
  # Standard isolation, keep SSH from IR jumpbox
  sudo $0 --mode firewall --mgmt-ip 10.0.100.5

  # Full isolation (no external access at all - use with caution)
  sudo $0 --mode full

  # Dry run to preview changes
  sudo $0 --mode firewall --mgmt-ip 10.0.100.5 --dry-run

  # Rollback isolation
  sudo $0 --rollback
EOF
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --mode)       MODE="$2"; shift 2 ;;
    --mgmt-ip)    MGMT_IP="$2"; shift 2 ;;
    --mgmt-port)  MGMT_PORT="$2"; shift 2 ;;
    --dry-run)    DRY_RUN=true; shift ;;
    --rollback)   ROLLBACK=true; shift ;;
    --help|-h)    usage; exit 0 ;;
    *) fail "Unknown option: $1. Use --help for usage." ;;
  esac
done

# ── Privilege Check ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Must run as root. Use: sudo $0"

# ── Header ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║    RANSOMWARE IR — HOST ISOLATION                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
log "Isolation script v$SCRIPT_VERSION started on $(hostname -f)"

# ── Rollback ──────────────────────────────────────────────────────────────────
if $ROLLBACK; then
  log "Rolling back isolation rules..."
  LATEST_BACKUP=$(ls -t /tmp/iptables-pre-isolation-*.rules 2>/dev/null | head -1)
  if [[ -z "$LATEST_BACKUP" ]]; then
    fail "No backup file found in /tmp. Cannot auto-rollback. Manually flush iptables."
  fi
  if ! $DRY_RUN; then
    iptables-restore < "$LATEST_BACKUP"
    if command -v ufw &>/dev/null; then
      ufw --force reset
      ufw enable
    fi
    ok "Rules restored from $LATEST_BACKUP"
  else
    echo "[DRY RUN] Would restore: $LATEST_BACKUP"
  fi
  exit 0
fi

# ── Pre-flight Checks ─────────────────────────────────────────────────────────
[[ "$MODE" == "firewall" && -z "$MGMT_IP" ]] && \
  fail "Firewall mode requires --mgmt-ip. Example: --mgmt-ip 10.0.100.5"

# Validate IP format
if [[ -n "$MGMT_IP" ]]; then
  if ! [[ "$MGMT_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
    fail "Invalid IP format: $MGMT_IP"
  fi
fi

# ── Backup Current Rules ──────────────────────────────────────────────────────
log "Backing up current iptables rules to $BACKUP_FILE"
if ! $DRY_RUN; then
  iptables-save > "$BACKUP_FILE"
  ok "Backup saved: $BACKUP_FILE"
else
  echo "[DRY RUN] Would save backup to: $BACKUP_FILE"
fi

# ── Current Network State ─────────────────────────────────────────────────────
log "Current established connections:"
ss -tnp | grep ESTABLISHED | head -20 || true
echo ""

# ── FIREWALL MODE ─────────────────────────────────────────────────────────────
apply_firewall_mode() {
  warn "Applying network isolation. Only $MGMT_IP:$MGMT_PORT will remain accessible."
  echo ""

  if command -v ufw &>/dev/null; then
    log "UFW detected — applying UFW isolation rules"

    if $DRY_RUN; then
      echo "[DRY RUN] Would run:"
      echo "  ufw --force reset"
      echo "  ufw default deny incoming"
      echo "  ufw default deny outgoing"
      echo "  ufw allow from $MGMT_IP to any port $MGMT_PORT proto tcp"
      echo "  ufw --force enable"
      return
    fi

    ufw --force reset
    ufw default deny incoming
    ufw default deny outgoing
    ufw allow from "$MGMT_IP" to any port "$MGMT_PORT" proto tcp
    ufw --force enable
    ok "UFW isolation applied"

  else
    log "Applying iptables isolation rules (no UFW detected)"

    if $DRY_RUN; then
      echo "[DRY RUN] Would run iptables isolation for mgmt IP: $MGMT_IP port $MGMT_PORT"
      return
    fi

    # Flush existing rules
    iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X
    iptables -t mangle -F; iptables -t mangle -X

    # Allow loopback
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established sessions so current SSH doesn't drop
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow management access from IR jumpbox only
    iptables -A INPUT  -s "$MGMT_IP" -p tcp --dport "$MGMT_PORT" -j ACCEPT
    iptables -A OUTPUT -d "$MGMT_IP" -p tcp --sport "$MGMT_PORT" -j ACCEPT

    # Drop everything else
    iptables -P INPUT   DROP
    iptables -P OUTPUT  DROP
    iptables -P FORWARD DROP

    ok "iptables isolation applied"
  fi

  # Save persistent rules
  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
  elif [[ -f /etc/iptables/rules.v4 ]]; then
    iptables-save > /etc/iptables/rules.v4
  fi
}

# ── FULL ISOLATION MODE ───────────────────────────────────────────────────────
apply_full_mode() {
  warn "FULL ISOLATION MODE — All network traffic will be blocked."
  warn "You will LOSE remote access. Ensure physical/IPMI access is available."
  echo ""

  read -r -p "Type CONFIRM to proceed with full isolation: " confirm
  [[ "$confirm" != "CONFIRM" ]] && { log "Aborted by operator."; exit 0; }

  if $DRY_RUN; then
    echo "[DRY RUN] Would apply full drop policy to all chains"
    return
  fi

  iptables -F; iptables -X
  iptables -P INPUT   DROP
  iptables -P OUTPUT  DROP
  iptables -P FORWARD DROP
  iptables -A INPUT  -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  ok "Full isolation applied — host is now network-isolated"
}

# ── Execute Mode ──────────────────────────────────────────────────────────────
case "$MODE" in
  firewall) apply_firewall_mode ;;
  full)     apply_full_mode ;;
  *) fail "Unknown mode: $MODE. Use: firewall, full" ;;
esac

# ── Post-Isolation Verification ───────────────────────────────────────────────
log "Verifying isolation..."
echo ""
echo "Current iptables rules:"
iptables -L -n -v 2>/dev/null | head -40 || true
echo ""

# ── Log Summary ───────────────────────────────────────────────────────────────
cat >> "$LOG_FILE" <<EOF

ISOLATION SUMMARY
=================
Host       : $(hostname -f)
Time       : $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Mode       : $MODE
Mgmt IP    : ${MGMT_IP:-"None (full isolation)"}
Mgmt Port  : $MGMT_PORT
Backup     : $BACKUP_FILE
Operator   : $(who am i 2>/dev/null | awk '{print $1}' || echo 'root')
EOF

echo ""
echo -e "${BOLD}${GREEN}━━━ ISOLATION APPLIED ━━━${NC}"
echo -e "${GREEN}Mode:${NC} $MODE"
[[ -n "$MGMT_IP" ]] && echo -e "${GREEN}Management access:${NC} $MGMT_IP:$MGMT_PORT"
echo -e "${GREEN}Log:${NC} $LOG_FILE"
echo -e "${GREEN}Backup:${NC} $BACKUP_FILE"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Run forensic-capture.sh to collect memory and disk images"
echo "  2. Document isolation timestamp in incident ticket"
echo "  3. Notify IR Lead and update incident status to CONTAINED"
echo "  4. To rollback: sudo $0 --rollback"
echo ""
