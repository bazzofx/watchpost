#!/usr/bin/env bash
# Install or update the Watchpost log collection agent on a Debian 12 / Ubuntu 22.04+ host.
# Safe to re-run. Installs a systemd service that tails this host's logs and ships them to a
# Watchpost server with an ingest token.
#
#   sudo ./deploy/agent/install-agent.sh --url http://192.168.8.178:8080
#   sudo ./deploy/agent/install-agent.sh --url https://siem.example.org --sources auth,web
#   sudo ./deploy/agent/install-agent.sh --url http://192.168.8.178:8080 --token-file /root/wp.token
#
# What it does, each step skipped or refreshed when already done:
#   1. checks python3 is 3.10 or newer (installs it from apt if missing)
#   2. creates the `watchpost-agent` system user and adds it to the `adm` group so it can
#      read /var/log (/var/log/auth.log is root:adm 0640)
#   3. installs agent.py and its sibling shipper.py to /usr/local/bin (the agent imports
#      shipper from its own directory, so both must live together)
#   4. writes /etc/watchpost-agent/agent.env (root:watchpost-agent 0640) from the template,
#      only if it does not exist yet, so your edits are never overwritten
#   5. installs deploy/agent/watchpost-agent.service, enables it, and starts it
#   6. prints what the agent found on this host
#
# The token is never taken from the command line if you use --token-file or the prompt, and it
# is never logged. Plain HTTP to a non-loopback host is refused by the agent unless you opt in
# (see the note this script prints), because the token would travel unencrypted.
set -euo pipefail

BIN_DIR=/usr/local/bin
ETC_DIR=/etc/watchpost-agent
ENV_FILE="$ETC_DIR/agent.env"
DOC_DIR=/usr/local/share/doc/watchpost-agent
UNIT=/etc/systemd/system/watchpost-agent.service
SERVICE=watchpost-agent
SERVICE_USER=watchpost-agent
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

URL=""
SOURCES=""
LOG_DIR=""
TOKEN=""
TOKEN_FILE=""

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url)        [ $# -ge 2 ] || { echo "--url needs a value" >&2; usage 2; }; URL="$2"; shift 2 ;;
        --sources)    [ $# -ge 2 ] || { echo "--sources needs a value" >&2; usage 2; }; SOURCES="$2"; shift 2 ;;
        --log-dir)    [ $# -ge 2 ] || { echo "--log-dir needs a value" >&2; usage 2; }; LOG_DIR="$2"; shift 2 ;;
        --token-file) [ $# -ge 2 ] || { echo "--token-file needs a value" >&2; usage 2; }; TOKEN_FILE="$2"; shift 2 ;;
        -h|--help)    usage 0 ;;
        *)            echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

log() { printf '==> %s\n' "$*"; }
warn() { printf '!!! %s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0 $*" >&2
    exit 1
fi
if [ -z "$URL" ]; then
    echo "--url is required (e.g. --url http://192.168.8.178:8080)" >&2
    exit 2
fi
case "$URL" in
    http://*|https://*) ;;
    *) echo "--url must start with http:// or https:// (got: $URL)" >&2; exit 2 ;;
esac

# --- the token (never from argv) -------------------------------------------------------

if [ -n "$TOKEN_FILE" ]; then
    [ -r "$TOKEN_FILE" ] || { echo "cannot read --token-file $TOKEN_FILE" >&2; exit 2; }
    TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
elif [ -t 0 ]; then
    printf 'Ingest token (Admin > API tokens in Watchpost, input hidden): ' >&2
    read -rs TOKEN
    printf '\n' >&2
fi
if [ -n "$TOKEN" ] && [ "${TOKEN#wp_}" = "$TOKEN" ]; then
    warn "the token does not start with wp_; Watchpost will reject it"
fi

# --- 1. python -------------------------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    log "installing python3"
    apt-get update -qq && apt-get install -y -qq python3
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "python3 3.10 or newer is required (found $(python3 -V 2>&1))" >&2
    exit 2
fi
log "python3 $(python3 -V 2>&1 | awk '{print $2}')"

# --- 2. service user -------------------------------------------------------------------

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating the $SERVICE_USER system user"
    useradd --system --no-create-home --shell /usr/sbin/nologin --groups adm "$SERVICE_USER"
else
    log "$SERVICE_USER already exists"
fi
# /var/log/auth.log is root:adm 0640, so membership of adm is what makes it readable.
if ! id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx adm; then
    log "adding $SERVICE_USER to the adm group"
    usermod -aG adm "$SERVICE_USER"
fi

# --- 3. the agent itself ---------------------------------------------------------------

log "installing the agent to $BIN_DIR"
install -d -m 0755 "$BIN_DIR" "$DOC_DIR"
install -m 0755 "$SRC/scripts/agent.py" "$BIN_DIR/agent.py"
install -m 0755 "$SRC/scripts/shipper.py" "$BIN_DIR/shipper.py"   # agent.py imports this sibling
if [ -f "$SRC/docs/AGENT.md" ]; then
    install -m 0644 "$SRC/docs/AGENT.md" "$DOC_DIR/AGENT.md"
fi

# --- 4. settings and secret ------------------------------------------------------------

install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$ETC_DIR"
if [ ! -f "$ENV_FILE" ]; then
    log "writing $ENV_FILE"
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC/deploy/agent/agent.env.example" "$ENV_FILE"
    sed -i "s|^WATCHPOST_AGENT_URL=.*|WATCHPOST_AGENT_URL=$URL|" "$ENV_FILE"
    if [ -n "$SOURCES" ]; then
        sed -i "s|^WATCHPOST_AGENT_SOURCES=.*|WATCHPOST_AGENT_SOURCES=$SOURCES|" "$ENV_FILE"
    fi
    if [ -n "$LOG_DIR" ]; then
        sed -i "s|^WATCHPOST_AGENT_LOG_DIR=.*|WATCHPOST_AGENT_LOG_DIR=$LOG_DIR|" "$ENV_FILE"
    fi
    if [ -n "$TOKEN" ]; then
        sed -i "s|^WATCHPOST_AGENT_TOKEN=.*|WATCHPOST_AGENT_TOKEN=$TOKEN|" "$ENV_FILE"
    fi
else
    log "$ENV_FILE already exists; leaving it untouched"
    # Fill in a token only when the file still has an empty one and one was supplied.
    if [ -n "$TOKEN" ] && grep -q '^WATCHPOST_AGENT_TOKEN=$' "$ENV_FILE"; then
        sed -i "s|^WATCHPOST_AGENT_TOKEN=.*|WATCHPOST_AGENT_TOKEN=$TOKEN|" "$ENV_FILE"
        log "stored the supplied token in $ENV_FILE"
    fi
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
unset TOKEN

if ! grep -Eq '^WATCHPOST_AGENT_TOKEN=wp_' "$ENV_FILE"; then
    warn "no token is set in $ENV_FILE; the agent cannot ingest until you add"
    warn "  WATCHPOST_AGENT_TOKEN=wp_...    then: systemctl restart $SERVICE"
fi

# --- 5. the service --------------------------------------------------------------------

if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found: this host has no systemd, so the service was not installed."
    warn "Run the agent by hand instead, for example:"
    warn "  sudo -u $SERVICE_USER python3 $BIN_DIR/agent.py --url $URL --token-env WATCHPOST_AGENT_TOKEN"
    exit 0
fi

log "installing $UNIT"
install -m 0644 "$SRC/deploy/agent/watchpost-agent.service" "$UNIT"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
log "service $SERVICE enabled and started"

# --- 6. what the agent can see here ----------------------------------------------------

log "sources detected on this host"
sudo -u "$SERVICE_USER" python3 "$BIN_DIR/agent.py" --url "$URL" --list-sources || \
    warn "could not list sources as $SERVICE_USER (check that /var/log is readable)"

sleep 2
if systemctl is-active --quiet "$SERVICE"; then
    log "$SERVICE is running"
else
    warn "$SERVICE is not running. Recent log lines:"
    journalctl -u "$SERVICE" -n 20 --no-pager >&2 || true
fi

case "$URL" in
    http://127.0.0.1*|http://localhost*|https://*) ;;
    http://*)
        warn ""
        warn "This is plain HTTP to a remote host, so the agent refuses to send the token."
        warn "On a trusted LAN, accept the trade-off by adding to $ENV_FILE:"
        warn "  WATCHPOST_AGENT_EXTRA_ARGS=--allow-insecure-http"
        warn "then: systemctl restart $SERVICE"
        warn "Better: put HTTPS in front of Watchpost and use an https:// URL."
        ;;
esac

log "done. Confirm data is arriving on the Watchpost server under Ingest > Recent batches."
log "Follow the agent's own log with: journalctl -u $SERVICE -f"
