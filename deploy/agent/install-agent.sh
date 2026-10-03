#!/usr/bin/env bash
# Install or update the Watchpost log collection agent on a Debian 12 / Ubuntu 22.04+ host.
# Safe to re-run. Installs a systemd service that tails this host's logs and ships them to a
# Watchpost server with an ingest token.
#
#   sudo ./deploy/agent/install-agent.sh --url http://127.0.0.1:8080
#   sudo ./deploy/agent/install-agent.sh --url https://siem.example.org --sources auth,web
#   sudo ./deploy/agent/install-agent.sh --url http://192.168.8.178:8080 --token-file /root/wp.token
#   sudo ./deploy/agent/install-agent.sh --url http://127.0.0.1:8080 --allow-insecure-http
#   sudo ./deploy/agent/install-agent.sh --dry-run          # show the plan and change nothing
#   sudo ./deploy/agent/install-agent.sh --uninstall        # remove it again (--yes skips the prompt)
#
# Agent flags go through --agent-args, e.g. --agent-args "--batch-lines 4000 --from-start".
#
# --allow-insecure-http accepts the ingest token travelling in clear text to a non-loopback host.
# --agent-args writes other agent flags into WATCHPOST_AGENT_EXTRA_ARGS in the env file, which is
# where the systemd unit passes them to agent.py. The flags that only inspect this host (--check,
# --list-sources, --dry-run) and --url are refused there: as a service they exit straight away
# instead of collecting anything, which looks exactly like a working install that sends nothing.
#
# What it does, each step skipped or refreshed when already done:
#   1. checks python3 is 3.10 or newer (installs it from apt if missing)
#   2. checks the URL the agent will be given, and reads the ingest token
#   3. creates the `watchpost-agent` system user and adds it to the `adm` group so it can
#      read /var/log (/var/log/auth.log is root:adm 0640)
#   4. installs agent.py and its sibling shipper.py to /usr/local/bin (the agent imports
#      shipper from its own directory, so both must live together)
#   5. writes /etc/watchpost-agent/agent.env (root:watchpost-agent 0640) from the template,
#      only if it does not exist yet, so your edits are never overwritten
#   6. installs deploy/agent/watchpost-agent.service, enables it, and starts it
#   7. verifies the token and prints what the agent found on this host
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
STATE_DIR=/var/lib/watchpost-agent
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

URL=""
SOURCES=""
LOG_DIR=""
TOKEN=""
TOKEN_FILE=""
UNINSTALL=0
ASSUME_YES=0
DRY_RUN=0
INSECURE_HTTP=0
AGENT_ARGS=""

usage() {
    # The comment block above is the help text. It ends at the first real command of the script,
    # so lines added to the header can never make the help drift out of step with the flags.
    sed -n '2,/^set -euo pipefail/p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' | sed '$d' || true
    exit "${1:-0}"
}

# Flags that belong to agent.py rather than to this installer. Naming them in the error is worth
# the trouble: they are passed to the service through WATCHPOST_AGENT_EXTRA_ARGS, and being told
# only "unknown option" sends people looking for a bug instead of at the env file.
# --dry-run and --allow-insecure-http are deliberately absent: the installer handles both itself
# (see --help), because a service cannot usefully run in the agent's dry-run mode.
AGENT_VALUE_FLAGS="--batch-lines --max-batches-per-pass --interval --year --cafile --state \
--source --hostname --source-prefix --token-env --max-retries"
AGENT_BOOL_FLAGS="--from-start --once --list-sources --check"

while [ $# -gt 0 ]; do
    case "$1" in
        --url)        [ $# -ge 2 ] || { echo "--url needs a value" >&2; usage 2; }; URL="$2"; shift 2 ;;
        --sources)    [ $# -ge 2 ] || { echo "--sources needs a value" >&2; usage 2; }; SOURCES="$2"; shift 2 ;;
        --log-dir)    [ $# -ge 2 ] || { echo "--log-dir needs a value" >&2; usage 2; }; LOG_DIR="$2"; shift 2 ;;
        --token-file) [ $# -ge 2 ] || { echo "--token-file needs a value" >&2; usage 2; }; TOKEN_FILE="$2"; shift 2 ;;
        --agent-args) [ $# -ge 2 ] || { echo "--agent-args needs a value" >&2; usage 2; }; AGENT_ARGS="$2"; shift 2 ;;
        --allow-insecure-http) INSECURE_HTTP=1; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --uninstall)  UNINSTALL=1; shift ;;
        --yes|-y)     ASSUME_YES=1; shift ;;
        -h|--help)    usage 0 ;;
        *)
            # Two lists, because a flag that takes no value must not be shown as "FLAG <value>":
            # argparse would reject that advice and the flag would look broken.
            case " $AGENT_VALUE_FLAGS " in
                *" $1 "*)
                    echo "$1 is an agent flag, not an installer flag; it takes a value." >&2
                    echo "Pass it through with --agent-args, for example:" >&2
                    echo "    --agent-args \"$1 <value>\"" >&2
                    echo "or set it in $ENV_FILE (WATCHPOST_AGENT_EXTRA_ARGS), then:" >&2
                    echo "    sudo systemctl restart $SERVICE" >&2
                    exit 2 ;;
            esac
            case " $AGENT_BOOL_FLAGS " in
                *" $1 "*)
                    echo "$1 is an agent flag, not an installer flag." >&2
                    echo "Pass it through with --agent-args, for example:" >&2
                    echo "    --agent-args \"$1\"" >&2
                    echo "or set it in $ENV_FILE (WATCHPOST_AGENT_EXTRA_ARGS), then:" >&2
                    echo "    sudo systemctl restart $SERVICE" >&2
                    exit 2 ;;
            esac
            echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

log() { printf '==> %s\n' "$*"; }
warn() { printf '!!! %s\n' "$*" >&2; }

# --- --agent-args is going into a long-running service, so it is checked ------------------
#
# These flags print something and exit, or point the agent somewhere else. Under Restart=always a
# service that exits is simply restarted, so a mistake here produces a unit that reports "running"
# while it ingests nothing -- the hardest kind of install failure to notice.
case " $AGENT_ARGS " in
    *" --check "*|*" --list-sources "*|*" --dry-run "*)
        echo "--agent-args: --check, --list-sources and --dry-run inspect this host and then exit," >&2
        echo "so the service would restart in a loop and never collect anything." >&2
        echo "Run them by hand instead, before or after installing:" >&2
        echo "    python3 $SRC/scripts/agent.py --check --url ${URL:-<watchpost-url>}" >&2
        echo "    python3 $SRC/scripts/agent.py --list-sources" >&2
        exit 2 ;;
esac
case " $AGENT_ARGS " in
    *" --url "*)
        echo "--agent-args: --url is set by this installer's --url, and the service reads" >&2
        echo "WATCHPOST_AGENT_URL from $ENV_FILE. Two URLs would silently disagree." >&2
        exit 2 ;;
esac
case " $AGENT_ARGS " in
    *" --once "*)
        warn "--agent-args --once makes the agent exit after one pass, and Restart=always then"
        warn "restarts it every RestartSec (5s) rather than every --interval. It does collect, but"
        warn "with a restart per pass; drop --once and let the service poll."
        ;;
esac
case " $AGENT_ARGS " in
    *" --state "*)
        warn "--agent-args --state overrides the unit's own --state. The agent may only write"
        warn "inside $STATE_DIR (ProtectSystem=strict plus StateDirectory), so a path elsewhere"
        warn "fails with a read-only file system."
        ;;
esac

# Set KEY=value in the env file, adding the line when it is missing. Written this way rather than
# with `sed -i` because a token or a flag list can contain sed's replacement characters (& and |),
# which sed would substitute instead of storing literally. Rewriting the file in place keeps its
# owner and mode.
set_env_value() {
    local key="$1" value="$2" line found=0 tmp
    tmp="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "${key}="*) printf '%s=%s\n' "$key" "$value"; found=1 ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$ENV_FILE" > "$tmp"
    [ "$found" = "1" ] || printf '%s=%s\n' "$key" "$value" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
}

# The value a KEY holds in the env file, or nothing if it is absent. Used for messages, so they can
# name what the service will actually use rather than what this command line asked for -- and so a
# setting that lives only in the env file is never referenced as a shell variable, which under
# `set -u` would abort the script with a bare "unbound variable".
env_value() {
    sed -n "s|^$1=||p" "$ENV_FILE" | head -n 1
}

# How long to wait for the unit to come up before calling it a failure. `systemctl restart` returns
# as soon as the process has been spawned, so a service that dies during startup can look started
# for a moment and a slow host can look dead. Polling beats a fixed sleep at both ends: nothing is
# reported until the state has settled, and a service that is already up costs no delay at all.
SERVICE_WAIT_SECONDS=10

# Prints the last state systemctl reported, so a failure can say *how* it is not running
# ("failed", "activating", "inactive") rather than just that it is not. The budget is read with a
# default rather than assumed: under `set -u` a missing assignment would otherwise abort the script
# with a bare "unbound variable", which is exactly how the token check died on the first real run.
wait_for_service() {
    local budget="${SERVICE_WAIT_SECONDS:-10}" waited=0 state=""
    while [ "$waited" -lt "$budget" ]; do
        state="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
        if [ "$state" = "active" ]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    printf '%s' "${state:-unknown}"
}

# Say so when an option cannot be applied because the env file already owns that setting, instead
# of appearing to accept it and quietly using the old value. A silently ignored --url is how a
# service ends up shipping to the wrong place after a "successful" install.
warn_if_ignored() {
    local key="$1" supplied="$2" flag="$3" current
    if [ -z "$supplied" ]; then
        return 0
    fi
    current="$(env_value "$key")"
    if [ "$current" = "$supplied" ]; then
        return 0
    fi
    warn "$flag was not applied: $ENV_FILE already sets $key=${current:-<empty>}"
    warn "  Only the token and --agent-args are updated on a re-run, so local edits survive."
    warn "  To change it: edit $ENV_FILE, then: sudo systemctl restart $SERVICE"
}

# Would the agent accept this URL? A plain-HTTP URL on a different host makes the service exit 2
# the moment it starts, and Restart=always turns that into a crash loop -- a confusing way to find
# out. The question is put to the agent's own shipper.check_url() rather than re-decided here, so
# this warning can never disagree with what the service actually does. Note that the host matters,
# not the spelling: 127.0.1.1 and [::1] are loopback too, while "127.0.0.1.example.com" is not.
url_refusal() {
    # Prints the agent's own reason when it would refuse this URL, nothing when it would accept
    # it. Exit 1 means refused; 2 means the question could not be answered.
    python3 - "$SRC/scripts" "$1" 2>/dev/null <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
try:
    import shipper
except Exception:
    sys.exit(2)
try:
    shipper.check_url(sys.argv[2], False)
except shipper.FatalError as exc:
    print(exc)
    sys.exit(1)
PY
}

check_url_acceptance() {
    if [ "$INSECURE_HTTP" = "1" ]; then
        warn "--allow-insecure-http given: the ingest token will travel in clear text to $URL."
        warn "Anyone able to read traffic on that network path can capture it. Fine on a trusted LAN,"
        warn "not over the internet. HTTPS in front of Watchpost is the better fix."
        return 0
    fi
    local status=0 refusal
    refusal="$(url_refusal "$URL")" || status=$?
    if [ "$status" = "1" ]; then
        warn "$URL: ${refusal:-the agent refuses plain HTTP to a non-loopback host}"
        warn "The service would exit with status 2 and restart in a loop. Either:"
        warn "  - point the agent at this machine:  --url http://127.0.0.1:8080"
        warn "  - or accept the token travelling in clear text:  --allow-insecure-http"
    elif [ "$status" != "0" ]; then
        # The agent's own code could not be asked, so compare the host literally. It errs towards
        # warning, which is the safe direction for a token in clear text.
        case "$URL" in
            https://*|http://localhost|http://localhost:*|http://127.0.0.1|http://127.0.0.1:*|http://\[::1\]|http://\[::1\]:*) ;;
            http://*)
                warn "could not put $URL to the agent's own check, so this is only a guess: if it is"
                warn "plain HTTP to another host, the service will refuse to send the token. See"
                warn "--allow-insecure-http, or point the agent at http://127.0.0.1:8080."
                ;;
        esac
    fi
}

uninstall() {
    if [ "$ASSUME_YES" != "1" ]; then
        printf 'Remove the Watchpost agent?\n' >&2
        printf '  - stop and disable %s, and delete %s\n' "$SERVICE" "$UNIT" >&2
        printf '  - delete %s/agent.py and %s/shipper.py\n' "$BIN_DIR" "$BIN_DIR" >&2
        printf '  - delete %s (this holds the ingest token)\n' "$ETC_DIR" >&2
        printf '  - delete %s (the position file)\n' "$STATE_DIR" >&2
        printf '  - delete the %s user\n' "$SERVICE_USER" >&2
        printf 'Type yes to continue: ' >&2
        read -r answer
        case "$answer" in
            yes|YES|Yes) ;;
            *) echo "aborted; nothing was changed" >&2; exit 0 ;;
        esac
    fi
    log "stopping and disabling $SERVICE"
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload 2>/dev/null || true
    # Clears the auto-restart state a crash-looping unit leaves behind.
    systemctl reset-failed "$SERVICE" 2>/dev/null || true
    log "removing installed files"
    rm -f "$BIN_DIR/agent.py" "$BIN_DIR/shipper.py"
    rm -rf "$DOC_DIR"
    log "removing configuration (the ingest token lives here)"
    rm -rf "$ETC_DIR"
    log "removing state"
    rm -rf "$STATE_DIR"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "removing the $SERVICE_USER user"
        userdel "$SERVICE_USER" 2>/dev/null || true
        groupdel "$SERVICE_USER" 2>/dev/null || true
    fi
    log "done"
    warn "the ingest token still exists in Watchpost: revoke it under Admin > API tokens"
    exit 0
}

# Agent flags the installer collected, plus anything passed straight through with --agent-args.
# Stored quoted so the env file can also be sourced by a shell (which the token check below does):
# an unquoted value containing spaces would be read as a command when sourced.
EXTRA="$AGENT_ARGS"
if [ "$INSECURE_HTTP" = "1" ]; then
    EXTRA="${EXTRA:+$EXTRA }--allow-insecure-http"
fi

# Everything installed comes from this tree, and the URL check below imports shipper.py from it.
# A copy of the installer on its own would otherwise fail much later, and less clearly.
for required in scripts/agent.py scripts/shipper.py deploy/agent/agent.env.example \
                deploy/agent/watchpost-agent.service; do
    if [ ! -r "$SRC/$required" ]; then
        echo "cannot read $SRC/$required" >&2
        echo "run this script from a full Watchpost checkout: the agent, its shipper, the env" >&2
        echo "template, and the unit file are all installed from that tree." >&2
        exit 2
    fi
done

# --- dry run: show the plan and the agent's own read-only view, change nothing ----------

dry_run() {
    echo "dry run: nothing on this system will be changed."
    echo
    echo "would install:  $BIN_DIR/agent.py"
    echo "                $BIN_DIR/shipper.py  (agent.py imports this sibling)"
    echo "                $DOC_DIR/AGENT.md"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        echo "would reuse:    the $SERVICE_USER user (already exists)"
    else
        echo "would create:   the $SERVICE_USER user, in the 'adm' group so it can read /var/log"
    fi
    echo "would write:    $ENV_FILE"
    if [ -f "$ENV_FILE" ]; then
        echo "                (exists; only the token and --agent-args lines would be updated)"
    else
        echo "                  WATCHPOST_AGENT_URL=$URL"
        echo "                  WATCHPOST_AGENT_SOURCES=${SOURCES:-auth,firewall,web,audit}"
        echo "                  WATCHPOST_AGENT_LOG_DIR=${LOG_DIR:-/var/log}"
        echo "                  WATCHPOST_AGENT_TOKEN=<pasted at the prompt>"
    fi
    [ -n "$EXTRA" ] && echo "                  WATCHPOST_AGENT_EXTRA_ARGS=\"$EXTRA\""
    echo "would install:  $UNIT, enabled and started"
    echo "would verify:   the token, and the sources below"
    echo
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is not installed on this host yet, so the two read-only listings below"
        echo "cannot be produced. Installing it is the first thing this installer would do:"
        echo "    apt-get install -y python3"
        exit 0
    fi
    if [ -n "$URL" ]; then
        echo "--- whether the agent would accept the URL (read-only) ---"
        check_url_acceptance
        echo
    fi
    echo "--- what the agent would collect (read-only) ---"
    # --source is deliberately not passed: --list-sources reports every source in the catalogue,
    # so filtering it here would promise a selection that it does not actually apply.
    python3 "$SRC/scripts/agent.py" --list-sources --log-dir "${LOG_DIR:-/var/log}" || true
    echo
    echo "--- what it would ship on the first pass (read-only) ---"
    # shellcheck disable=SC2086  # EXTRA is a flag list, so it must be word-split here.
    python3 "$SRC/scripts/agent.py" --dry-run --url "$URL" --log-dir "${LOG_DIR:-/var/log}" \
        --source "${SOURCES:-all}" ${EXTRA} || true
    echo
    echo "note: as $(id -un) rather than $SERVICE_USER, so a file shown as readable here may still"
    echo "      be unreadable to the service (membership of 'adm' is what the install adds)."
    exit 0
}

if [ "$DRY_RUN" = "1" ]; then
    dry_run
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0 $*" >&2
    exit 1
fi
if [ "$UNINSTALL" = "1" ]; then
    uninstall
fi
if [ -z "$URL" ]; then
    echo "--url is required (e.g. --url http://192.168.8.178:8080)" >&2
    exit 2
fi
case "$URL" in
    http://*|https://*) ;;
    *) echo "--url must start with http:// or https:// (got: $URL)" >&2; exit 2 ;;
esac
# --- 1. python -------------------------------------------------------------------------
#
# Before anything else: everything below needs it, including the URL question, which is put to
# the agent's own code rather than re-decided here.

if ! command -v python3 >/dev/null 2>&1; then
    log "installing python3"
    apt-get update -qq && apt-get install -y -qq python3
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "python3 3.10 or newer is required (found $(python3 -V 2>&1))" >&2
    exit 2
fi
log "python3 $(python3 -V 2>&1 | awk '{print $2}')"

# --- 2. will the agent accept this URL? ------------------------------------------------

check_url_acceptance

# --- 3. the token (never from argv) ----------------------------------------------------

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

# --- 4. service user -------------------------------------------------------------------

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

# --- 5. the agent itself ---------------------------------------------------------------

log "installing the agent to $BIN_DIR"
install -d -m 0755 "$BIN_DIR" "$DOC_DIR"
install -m 0755 "$SRC/scripts/agent.py" "$BIN_DIR/agent.py"
install -m 0755 "$SRC/scripts/shipper.py" "$BIN_DIR/shipper.py"   # agent.py imports this sibling
if [ -f "$SRC/docs/AGENT.md" ]; then
    install -m 0644 "$SRC/docs/AGENT.md" "$DOC_DIR/AGENT.md"
fi

# --- 6. settings and secret ------------------------------------------------------------

install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$ETC_DIR"
if [ ! -f "$ENV_FILE" ]; then
    log "writing $ENV_FILE"
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC/deploy/agent/agent.env.example" "$ENV_FILE"
    set_env_value WATCHPOST_AGENT_URL "$URL"
    if [ -n "$SOURCES" ]; then
        set_env_value WATCHPOST_AGENT_SOURCES "$SOURCES"
    fi
    if [ -n "$LOG_DIR" ]; then
        set_env_value WATCHPOST_AGENT_LOG_DIR "$LOG_DIR"
    fi
    if [ -n "$TOKEN" ]; then
        set_env_value WATCHPOST_AGENT_TOKEN "$TOKEN"
    fi
    if [ -n "$EXTRA" ]; then
        set_env_value WATCHPOST_AGENT_EXTRA_ARGS "\"$EXTRA\""
    fi
else
    log "$ENV_FILE already exists; only the token and --agent-args are updated in it"
    # A token, or agent flags, supplied on this command line are explicit intent and must not be
    # thrown away. Only those two lines are written; every other edit in the file is preserved.
    if [ -n "$TOKEN" ]; then
        set_env_value WATCHPOST_AGENT_TOKEN "$TOKEN"
        log "stored the supplied token in $ENV_FILE"
    fi
    if [ -n "$EXTRA" ]; then
        set_env_value WATCHPOST_AGENT_EXTRA_ARGS "\"$EXTRA\""
        log "stored agent flags in $ENV_FILE: $EXTRA"
    fi
    # The remaining settings belong to the file once it exists, which is what keeps local edits
    # from being overwritten by a re-run. Saying so beats accepting an option and then quietly
    # using the old value: that is how a service ends up shipping to the wrong URL after an
    # install that reported success.
    warn_if_ignored WATCHPOST_AGENT_URL "$URL" "--url"
    warn_if_ignored WATCHPOST_AGENT_SOURCES "$SOURCES" "--sources"
    warn_if_ignored WATCHPOST_AGENT_LOG_DIR "$LOG_DIR" "--log-dir"
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
unset TOKEN

if ! grep -Eq '^WATCHPOST_AGENT_TOKEN=wp_' "$ENV_FILE"; then
    warn "no token is set in $ENV_FILE; the agent cannot ingest until you add"
    warn "  WATCHPOST_AGENT_TOKEN=wp_...    then: systemctl restart $SERVICE"
fi

# --- 7. the service --------------------------------------------------------------------

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

# --- 8. what the agent can see here ----------------------------------------------------

log "sources detected on this host, as $SERVICE_USER"
# Sourced rather than passed as arguments, so this is the same URL, log directory, and token the
# service will use. It also keeps the token out of ps.
if sudo -u "$SERVICE_USER" bash -c \
    '. "$1"; exec python3 "$2" --url "$WATCHPOST_AGENT_URL" --log-dir "$WATCHPOST_AGENT_LOG_DIR" --list-sources' \
    _ "$ENV_FILE" "$BIN_DIR/agent.py"; then
    :
else
    warn "could not list sources as $SERVICE_USER (check that /var/log is readable)"
fi

# Poll rather than sleep a fixed amount: `systemctl restart` has already returned by now, but the
# unit may still be settling, and a hard-coded sleep is either too short for a slow host or wasted
# time on a fast one.
service_state="$(wait_for_service)"
if [ "$service_state" = "active" ]; then
    log "$SERVICE is running"
else
    warn "$SERVICE is not active after ${SERVICE_WAIT_SECONDS:-10}s (systemctl reports '$service_state')."
    warn "Recent log lines:"
    journalctl -u "$SERVICE" -n 20 --no-pager >&2 || true
fi

# --- 9. verify the token, and the url the service will actually use ---------------------
#
# The env file is sourced inside the child rather than passed on the command line, so the token
# never appears in ps. Values are written quoted for exactly this reason. The check posts an empty
# body, which the server answers 400 "upload is empty" *after* authenticating, so a 400 means the
# token is good and nothing was stored.

if grep -Eq '^WATCHPOST_AGENT_TOKEN=wp_' "$ENV_FILE"; then
    log "verifying the token against the configured URL (writes nothing)"
    # `set -a` is load-bearing. Sourcing the env file assigns *shell* variables, and a shell
    # variable is not part of the environment, so the python3 child would see no
    # WATCHPOST_AGENT_TOKEN at all and report "no ingest token" for a token that is perfectly
    # good. It also matters that the flag list is word-split here and that the URL comes from the
    # file, since that is what the service will use. systemd's EnvironmentFile= does export these,
    # so only this check was ever affected -- the service itself was fine.
    if sudo -u "$SERVICE_USER" bash -c \
        'set -a; . "$1"; set +a; exec python3 "$2" --url "$WATCHPOST_AGENT_URL" $WATCHPOST_AGENT_EXTRA_ARGS --check' \
        _ "$ENV_FILE" "$BIN_DIR/agent.py"; then
        log "the server accepted the agent's token"
    else
        checked_url="$(env_value WATCHPOST_AGENT_URL)"
        warn "the token check did not pass. Which line appeared above decides what it means:"
        warn "  - 'no ingest token' means this script failed to hand the token to the agent, not that"
        warn "    the token is bad: the service reads $ENV_FILE itself, so check Agents in Watchpost"
        warn "    before changing anything here."
        warn "  - 401 or 403 means the token really is wrong or revoked: create a new one under"
        warn "    Admin > API tokens."
        warn "  - a connection error means nothing is listening on ${checked_url:-$URL}."
    fi
else
    warn "skipping the token check: no wp_ token is set in $ENV_FILE"
fi

log "done. To confirm data is arriving, open Agents in Watchpost:"
log "  the row for this host shows each source with accepted and rejected counts."
log "  rejected > 0 usually means a log file whose contents do not match the format chosen for"
log "  it (see --list-sources above). Events appear only for lines written after this install:"
log "  the agent starts at the end of each file unless you pass --agent-args --from-start."
log "Follow the agent's own log with: journalctl -u $SERVICE -f"
