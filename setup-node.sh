#!/usr/bin/env bash
set -euo pipefail

# =========[ SkyOps Swarm - Bootstrap WIFI -> ETH ]=========
# Usage :
#   sudo ./bootstrap-wifi-to-eth.sh [--iface IFACE] [--no-upgrade] [--keep-wifi] [--wifi-backup]
# --keep-wifi    : laisse le Wi-Fi tel quel (par défaut il est coupé après succès ETH)
# --wifi-backup  : garde le Wi-Fi mais SANS gateway, jamais route par défaut (secours SSH)
# ===========================================================

GATEWAY="10.10.0.1"
DNS_PRIMARY="10.10.0.1"
DNS_SECONDARY="1.1.1.1"
CON_NAME="vlan10"
IP_PREFIX="/24"
PING_TIMEOUT=2
ETH_LINK_WAIT=20

# Route metrics : plus petit = plus prioritaire
ETH_METRIC=100
WIFI_METRIC=600

declare -A HOST_IP_MAP=(
  [mpc-manager-01]="10.10.0.10"
  [pi5-master-01]="10.10.0.11"
  [pi5-master-02]="10.10.0.12"
  [pi5-worker-01]="10.10.0.21"
  [pi5-worker-02]="10.10.0.22"
  [pi4-worker-01]="10.10.0.31"
  [pi4-worker-02]="10.10.0.32"
  [pi4-worker-03]="10.10.0.33"
  [pi4-worker-04]="10.10.0.34"
)

IFACE=""
DO_UPGRADE="true"
KEEP_WIFI="false"
WIFI_BACKUP="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="${2:-}"; shift 2 ;;
    --no-upgrade) DO_UPGRADE="false"; shift ;;
    --keep-wifi) KEEP_WIFI="true"; shift ;;
    --wifi-backup) WIFI_BACKUP="true"; KEEP_WIFI="true"; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--iface IFACE] [--no-upgrade] [--keep-wifi] [--wifi-backup]"
      exit 0 ;;
    *) echo "Option inconnue: $1"; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;36m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; }

require_root() { [[ $EUID -eq 0 ]] || { err "Exécute en root (sudo)."; exit 1; }; }

detect_iface() {
  if [[ -n "$IFACE" ]]; then
    ip link show "$IFACE" >/dev/null 2>&1 || { err "Interface $IFACE introuvable"; exit 1; }
    return
  fi
  local candidates=(eth0 end0 enp0s* enp1s* enx* en*)
  for c in "${candidates[@]}"; do
    if ip link show "$c" >/dev/null 2>&1; then IFACE="$c"; break; fi
  done
  [[ -n "$IFACE" ]] || { err "Aucune interface Ethernet détectée. --iface IFACE ?"; exit 1; }
  log "Interface détectée : $IFACE"
}

ensure_nm() {
  if ! command -v nmcli >/dev/null 2>&1; then
    log "Installation de NetworkManager…"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y network-manager
    systemctl enable NetworkManager
    systemctl restart NetworkManager
  else
    log "NetworkManager présent."
  fi
}

apt_upgrade() {
  if [[ "$DO_UPGRADE" == "true" ]]; then
    log "Mise à jour APT…"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
  else
    warn "Upgrade APT ignoré (--no-upgrade)."
  fi
}

resolve_ip() {
  local hn; hn="$(hostname -s)"
  local ip="${HOST_IP_MAP[$hn]:-}"
  [[ -n "$ip" ]] || { err "Aucune IP mappée pour hostname '$hn'."; exit 1; }
  echo "$ip"
}

wait_eth_link() {
  log "Attente du link UP sur $IFACE (max ${ETH_LINK_WAIT}s)…"
  local i=0
  while [[ $i -lt $ETH_LINK_WAIT ]]; do
    if [[ "$(cat /sys/class/net/$IFACE/operstate 2>/dev/null || echo down)" == "up" ]]; then
      log "Link $IFACE = UP."
      return 0
    fi
    sleep 1; ((i++))
  done
  warn "Link $IFACE toujours DOWN (câble/port ?) — on continue quand même."
}

nm_cleanup_eth_profiles() {
  while IFS= read -r name; do
    [[ "$name" == "$CON_NAME" ]] && continue
    log "Suppression profil ethernet existant : $name"
    nmcli con down "$name" >/dev/null 2>&1 || true
    nmcli con delete "$name" >/dev/null 2>&1 || true
  done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="ethernet"{print $1}')
}

apply_static_eth() {
  local ip="$1"
  log "Profil $CON_NAME sur $IFACE → $ip$IP_PREFIX (GW $GATEWAY, DNS $DNS_PRIMARY $DNS_SECONDARY, metric $ETH_METRIC)"
  if nmcli -t -f NAME con show | grep -Fx "$CON_NAME" >/dev/null 2>&1; then
    nmcli con mod "$CON_NAME" \
      connection.interface-name "$IFACE" \
      connection.autoconnect yes \
      ipv4.method manual \
      ipv4.addresses "$ip$IP_PREFIX" \
      ipv4.gateway "$GATEWAY" \
      ipv4.dns "$DNS_PRIMARY $DNS_SECONDARY" \
      ipv4.route-metric "$ETH_METRIC" \
      ipv6.method ignore
  else
    nmcli con add type ethernet ifname "$IFACE" con-name "$CON_NAME" ip4 "$ip$IP_PREFIX" gw4 "$GATEWAY"
    nmcli con mod "$CON_NAME" ipv4.dns "$DNS_PRIMARY $DNS_SECONDARY" ipv6.method ignore connection.autoconnect yes ipv4.route-metric "$ETH_METRIC"
  fi
  nmcli con up "$CON_NAME"
}

configure_wifi_backup() {
  # Met TOUS les profils Wi-Fi en "secours" : pas de défaut, pas de gateway, metric élevé
  local changed="false"
  while IFS= read -r wname; do
    changed="true"
    log "Configuration Wi-Fi secours pour le profil : $wname"
    nmcli con mod "$wname" \
      ipv4.never-default yes \
      ipv4.gateway "" \
      ipv4.route-metric "$WIFI_METRIC" \
      ipv6.method ignore \
      connection.autoconnect yes || true

    # Si le profil est up, on le recycle pour appliquer les routes
    nmcli -g GENERAL.STATE con show "$wname" | grep -q "activated" && {
      nmcli con down "$wname" || true
      nmcli con up "$wname" || true
    }
  done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="wifi"{print $1}')

  if [[ "$changed" == "false" ]]; then
    warn "Aucun profil Wi-Fi trouvé. Rien à faire pour le backup Wi-Fi."
  else
    log "Wi-Fi en mode secours configuré (no default route, metric $WIFI_METRIC)."
  fi
}

verify_paths() {
  local ip="$1"
  log "Vérifications :"
  ip -br a || true
  ip route || true
  log "Ping GW ($GATEWAY)…"
  ping -c3 -W "$PING_TIMEOUT" "$GATEWAY" || { err "GW injoignable depuis $IFACE. On NE coupe PAS le Wi-Fi."; exit 1; }
  log "Ping Internet (8.8.8.8)…"
  ping -c3 -W "$PING_TIMEOUT" 8.8.8.8 || warn "Pas d'Internet — facultatif si isolé."
  log "Résolution DNS (google.com)…"
  getent hosts google.com || warn "DNS non résolu — vérifier DNS."
}

maybe_disable_wifi_and_reboot() {
  if [[ "$KEEP_WIFI" == "true" ]]; then
    warn "--keep-wifi actif → le Wi-Fi reste opérationnel."
    return 0
  fi
  # Sinon on désactive tout Wi-Fi
  while IFS= read -r wname; do
    log "Désactivation autoconnect Wi-Fi : $wname"
    nmcli con mod "$wname" connection.autoconnect no || true
    log "Down Wi-Fi : $wname"
    nmcli con down "$wname" || true
  done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="wifi"{print $1}')

  log "✅ ETH opérationnel, Wi-Fi désactivé. Reboot dans 3s…"
  sleep 3
  reboot
}

main() {
  require_root
  detect_iface
  wait_eth_link
  apt_upgrade
  ensure_nm

  local ip; ip="$(resolve_ip)"
  nm_cleanup_eth_profiles
  apply_static_eth "$ip"

  if [[ "$WIFI_BACKUP" == "true" ]]; then
    configure_wifi_backup   # garde le Wi-Fi mais sans gateway / never-default
  fi

  verify_paths "$ip"

  echo
  log "Résumé : hostname=$(hostname -s)  iface=$IFACE  ip=$ip$IP_PREFIX  gw=$GATEWAY  dns=$DNS_PRIMARY,$DNS_SECONDARY"
  echo "Routes en place :"
  ip route | sed 's/^/  /'
  echo

  maybe_disable_wifi_and_reboot
}

main "$@"