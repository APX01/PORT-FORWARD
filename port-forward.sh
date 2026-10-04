#!/bin/sh
# port-forward.sh - TCP+UDP port forwarding with iptables (Ubuntu 22.04)
#
# Usage:
#   port-forward.sh IP PORT          add forward  (local PORT -> IP:PORT, tcp+udp)
#   port-forward.sh add IP PORT      same as above
#   port-forward.sh del IP PORT      remove forward (or: del PORT)
#   port-forward.sh list             show configured forwards
#   port-forward.sh apply            re-apply saved rules (used by systemd at boot)
#
# Persistence: rules are stored in /etc/port-forward/rules.conf and re-applied
# at boot by the port-forward.service systemd unit. Only our own iptables
# chains (PF_PRE, PF_POST, PF_FWD) are touched; other firewall rules are left alone.

set -eu

NAME=port-forward
ROOT=${PF_ROOT:-}                       # testing only; leave empty in production
BIN=$ROOT/usr/local/sbin/$NAME
CONF_DIR=$ROOT/etc/$NAME
CONF=$CONF_DIR/rules.conf
UNIT=$ROOT/etc/systemd/system/$NAME.service
SYSCTL_FILE=$ROOT/etc/sysctl.d/99-$NAME.conf
MODLOAD_FILE=$ROOT/etc/modules-load.d/$NAME.conf
MODPROBE_FILE=$ROOT/etc/modprobe.d/$NAME.conf
LOCK=${PF_LOCK:-/run/$NAME.lock}
CT_MAX_TARGET=${CT_MAX:-524288}         # override: CT_MAX=1048576 ./port-forward.sh ...
CT_EST_TARGET=${CT_EST:-86400}          # tcp established timeout in seconds (kernel default: 432000 = 5 days)

log()  { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage:
  $0 IP PORT          add forward (tcp+udp): this server:PORT -> IP:PORT
  $0 add IP PORT      same as above
  $0 del IP PORT      remove a forward (also: del PORT)
  $0 list             list forwards
  $0 apply            re-apply saved rules
EOF
}

require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

lock() {
    exec 9>"$LOCK"
    flock 9
}

valid_ip() {
    case $1 in
        ''|*[!0-9.]*|.*|*.) return 1 ;;
    esac
    _oifs=$IFS
    IFS=.
    set -- $1
    IFS=$_oifs
    [ $# -eq 4 ] || return 1
    for _o in "$@"; do
        case $_o in
            ''|*[!0-9]*|0?*) return 1 ;;     # empty, non-digit, or leading zero (octal)
        esac
        [ "${#_o}" -le 3 ] && [ "$_o" -le 255 ] || return 1
    done
    case $1 in
        0|127) return 1 ;;                   # 0.x.x.x and 127.x.x.x are not valid targets
    esac
    return 0
}

valid_port() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
    esac
    [ "${#1}" -le 5 ] && [ "$1" -le 65535 ]
}

ensure_deps() {
    if ! command -v iptables-restore >/dev/null 2>&1; then
        log "installing iptables..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables >/dev/null \
            || die "could not install iptables"
    fi
    for _c in iptables iptables-restore flock sysctl; do
        command -v "$_c" >/dev/null 2>&1 || die "required command not found: $_c"
    done

    # conntrack CLI is needed by "del" to drop already-established flows (best effort)
    if ! command -v conntrack >/dev/null 2>&1; then
        log "installing conntrack..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq conntrack >/dev/null 2>&1 \
            || warn "could not install conntrack; 'del' will not drop existing connections"
    fi
}

ensure_conf() {
    mkdir -p "$CONF_DIR"
    [ -f "$CONF" ] || : > "$CONF"
}

# ---- kernel settings: ip_forward + conntrack (checked and applied) ---------
ensure_system() {
    _cur=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
    if [ "$_cur" != "1" ]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null || die "cannot set net.ipv4.ip_forward"
        log "net.ipv4.ip_forward: $_cur -> 1"
    else
        log "net.ipv4.ip_forward: already 1"
    fi

    modprobe nf_conntrack 2>/dev/null || true
    _cur=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
    _want=$CT_MAX_TARGET
    if [ "$_cur" -gt "$_want" ]; then _want=$_cur; fi

    _ct_ok=0
    if [ "$_cur" -eq 0 ]; then
        warn "net.netfilter.nf_conntrack_max not available (container/VPS restriction?)"
    elif [ "$_cur" -lt "$_want" ]; then
        if sysctl -w net.netfilter.nf_conntrack_max="$_want" >/dev/null; then
            log "net.netfilter.nf_conntrack_max: $_cur -> $_want"
            _ct_ok=1
        else
            warn "cannot set nf_conntrack_max"
        fi
    else
        log "net.netfilter.nf_conntrack_max: already $_cur"
        _ct_ok=1
    fi

    # hash table size (~max/4) keeps lookups fast with many connections
    _hs=/sys/module/nf_conntrack/parameters/hashsize
    _hwant=$((_want / 4))
    if [ "$_ct_ok" -eq 1 ] && [ -w "$_hs" ]; then
        _hcur=$(cat "$_hs" 2>/dev/null || echo 0)
        if [ "$_hcur" -lt "$_hwant" ]; then
            echo "$_hwant" > "$_hs" 2>/dev/null \
                && log "nf_conntrack hashsize: $_hcur -> $_hwant" \
                || warn "cannot set nf_conntrack hashsize"
        fi
    fi

    # shorter established-TCP timeout: stale entries (dead mobile clients) would
    # otherwise sit in the table for 5 days and eventually fill it
    _est_key=net.netfilter.nf_conntrack_tcp_timeout_established
    _est_ok=0
    _est_cur=$(sysctl -n "$_est_key" 2>/dev/null || echo 0)
    if [ "$_est_cur" -eq 0 ]; then
        warn "$_est_key not available"
    elif [ "$_est_cur" -eq "$CT_EST_TARGET" ]; then
        log "$_est_key: already $_est_cur"
        _est_ok=1
    elif sysctl -w "$_est_key=$CT_EST_TARGET" >/dev/null 2>&1; then
        log "$_est_key: $_est_cur -> $CT_EST_TARGET"
        _est_ok=1
    else
        warn "cannot set $_est_key"
    fi

    # persist across reboots
    mkdir -p "$(dirname "$SYSCTL_FILE")" "$(dirname "$MODLOAD_FILE")" "$(dirname "$MODPROBE_FILE")"
    {
        echo "# managed by $NAME"
        echo "net.ipv4.ip_forward = 1"
        if [ "$_ct_ok" -eq 1 ]; then echo "net.netfilter.nf_conntrack_max = $_want"; fi
        if [ "$_est_ok" -eq 1 ]; then echo "$_est_key = $CT_EST_TARGET"; fi
    } > "$SYSCTL_FILE"
    echo "nf_conntrack" > "$MODLOAD_FILE"
    echo "options nf_conntrack hashsize=$_hwant" > "$MODPROBE_FILE"
}

# ---- iptables rules ---------------------------------------------------------
# Rebuilds our three chains atomically from the given conf file.
apply_rules() {
    _src=$1
    _tmp=$(mktemp)
    {
        echo "*nat"
        echo ":PF_PRE - [0:0]"
        echo ":PF_POST - [0:0]"
        echo "-F PF_PRE"
        echo "-F PF_POST"
        while read -r _aip _aport _arest; do
            [ -n "$_aip" ] || continue
            if ! valid_ip "$_aip" || ! valid_port "$_aport"; then
                warn "skipping invalid line: $_aip $_aport"
                continue
            fi
            for _ap in tcp udp; do
                echo "-A PF_PRE -p $_ap --dport $_aport -j DNAT --to-destination $_aip:$_aport"
                echo "-A PF_POST -d $_aip -p $_ap --dport $_aport -j MASQUERADE"
            done
        done < "$_src"
        echo "COMMIT"
        echo "*filter"
        echo ":PF_FWD - [0:0]"
        echo "-F PF_FWD"
        echo "-A PF_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        while read -r _aip _aport _arest; do
            [ -n "$_aip" ] || continue
            valid_ip "$_aip" && valid_port "$_aport" || continue
            for _ap in tcp udp; do
                echo "-A PF_FWD -d $_aip -p $_ap --dport $_aport -j ACCEPT"
            done
        done < "$_src"
        echo "COMMIT"
    } > "$_tmp"

    if ! iptables-restore -w 5 --noflush < "$_tmp" 2>/dev/null &&
       ! iptables-restore --noflush < "$_tmp"; then
        rm -f "$_tmp"
        warn "iptables-restore failed; nothing was changed"
        return 1
    fi
    rm -f "$_tmp"

    # make sure the built-in chains jump to ours (idempotent)
    iptables -w 5 -t nat -C PREROUTING  -j PF_PRE  2>/dev/null || iptables -w 5 -t nat -I PREROUTING  1 -j PF_PRE
    iptables -w 5 -t nat -C POSTROUTING -j PF_POST 2>/dev/null || iptables -w 5 -t nat -I POSTROUTING 1 -j PF_POST
    iptables -w 5       -C FORWARD     -j PF_FWD  2>/dev/null || iptables -w 5       -I FORWARD     1 -j PF_FWD
}

# ---- install: copy script + systemd unit for boot persistence ---------------
install_self() {
    _self=$(readlink -f "$0" 2>/dev/null || echo "")
    [ -f "$_self" ] || die "run the script from a file (not via a pipe) so it can be installed"
    mkdir -p "$(dirname "$BIN")" "$(dirname "$UNIT")"
    if [ "$_self" != "$BIN" ] && ! cmp -s "$_self" "$BIN" 2>/dev/null; then
        cp "$_self" "$BIN"
        chmod 0755 "$BIN"
        log "installed $BIN"
    fi

    _newunit=$(mktemp)
    cat > "$_newunit" <<EOF
[Unit]
Description=Port forwarding rules (iptables)
Wants=network-pre.target
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/$NAME apply

[Install]
WantedBy=multi-user.target
EOF
    if ! cmp -s "$_newunit" "$UNIT" 2>/dev/null; then
        cp "$_newunit" "$UNIT"
        chmod 0644 "$UNIT"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
            systemctl enable "$NAME.service" >/dev/null 2>&1 \
                && log "enabled $NAME.service (rules survive reboot)" \
                || warn "could not enable $NAME.service"
        fi
    fi
    rm -f "$_newunit"
}

# ---- commands ---------------------------------------------------------------
cmd_add() {
    [ $# -eq 2 ] || { usage; exit 1; }
    _ip=$1
    _port=$2
    valid_ip "$_ip"     || die "invalid IP: $_ip"
    valid_port "$_port" || die "invalid port: $_port (1-65535)"

    require_root
    lock
    ensure_deps
    ensure_conf

    if grep -qxF "$_ip $_port" "$CONF"; then
        log "forward already exists: $_port -> $_ip:$_port (re-applying)"
        ensure_system
        apply_rules "$CONF"
        install_self
        return 0
    fi

    _other=$(awk -v p="$_port" '$2==p {print $1; exit}' "$CONF")
    [ -z "$_other" ] || die "port $_port already forwarded to $_other; remove it first: $0 del $_port"

    # a forward on a port this server listens on would hijack that service (e.g. SSH)
    if command -v ss >/dev/null 2>&1 &&
       ss -H -lntu 2>/dev/null | awk -v p=":$_port" \
           '{ n=$5; if (length(n) >= length(p) && substr(n, length(n)-length(p)+1) == p) f=1 } END { exit !f }'
    then
        die "port $_port is used by a local service on this server; forwarding it would break that service"
    fi

    ensure_system

    _new=$(mktemp -p "$CONF_DIR")
    cp "$CONF" "$_new"
    echo "$_ip $_port" >> "$_new"
    if ! apply_rules "$_new"; then
        rm -f "$_new"
        exit 1
    fi
    chmod 0644 "$_new"
    mv "$_new" "$CONF"
    install_self
    log "OK: $_port (tcp+udp) -> $_ip:$_port"
}

cmd_del() {
    [ $# -eq 1 ] || [ $# -eq 2 ] || { usage; exit 1; }
    if [ $# -eq 2 ]; then _ip=$1; _port=$2; else _ip=""; _port=$1; fi
    if [ -n "$_ip" ]; then valid_ip "$_ip" || die "invalid IP: $_ip"; fi
    valid_port "$_port" || die "invalid port: $_port"

    require_root
    lock
    ensure_deps
    ensure_conf

    awk -v i="$_ip" -v p="$_port" '$2==p && (i=="" || $1==i) {f=1} END{exit !f}' "$CONF" \
        || die "no such forward in $CONF"

    _new=$(mktemp -p "$CONF_DIR")
    awk -v i="$_ip" -v p="$_port" '!($2==p && (i=="" || $1==i))' "$CONF" > "$_new"
    if ! apply_rules "$_new"; then
        rm -f "$_new"
        exit 1
    fi
    chmod 0644 "$_new"
    mv "$_new" "$CONF"

    # drop already-established flows so old connections stop immediately (best effort)
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -p tcp --orig-port-dst "$_port" >/dev/null 2>&1 || true
        conntrack -D -p udp --orig-port-dst "$_port" >/dev/null 2>&1 || true
    fi
    log "removed forward for port $_port"
}

cmd_list() {
    if [ ! -s "$CONF" ]; then
        echo "no forwards configured"
        return 0
    fi
    echo "LOCAL PORT  ->  TARGET (tcp+udp)"
    while read -r _ip _port _rest; do
        [ -n "$_ip" ] || continue
        echo "$_port  ->  $_ip:$_port"
    done < "$CONF"
}

cmd_apply() {
    require_root
    lock
    ensure_deps
    ensure_conf
    if [ -s "$CONF" ]; then
        ensure_system
    fi
    apply_rules "$CONF"
    log "rules applied"
}

case ${1:-} in
    add)                    shift; cmd_add "$@" ;;
    del|delete|remove|rm)   shift; cmd_del "$@" ;;
    list|ls)                cmd_list ;;
    apply)                  cmd_apply ;;
    ''|-h|--help|help)      usage ;;
    *)                      cmd_add "$@" ;;
esac
