#!/usr/bin/env bash
set -euo pipefail

# =========[ SkyOps Swarm - Node Network Bootstrap ]=========
# Usage (simple) : sudo ./setup-node.sh
# Options:
#   --iface IFACE     : forcer l'interface (par défaut: auto / eth0 prioritaire)
#   --dry-run         : ne fait qu'afficher ce qui serait exécuté
#   --no-upgrade      : saute apt update/upgrade
#
# Requis : Debian/Ubuntu (Raspberry Pi OS Bookworm OK), sudo
# ===========================================================

# ---------- CONFIG GLOBALE ----------
GATEWAY="10.10.0.1"
DNS_PRIMARY="10.10.0.1"
DNS_SECONDARY="1.1.1.1"
CON_NAME="vlan10"          # nom du profil NetworkManager
IP_PREFIX="/24"            # masque

# Table "hostname -> IP" (à adapter si besoin)
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

# ---------- PARSING OPTIONS ----------
IFACE=""
DRY_RUN="false"
DO_UPGRADE="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    --no-upgrade) DO_UPGRADE="false"; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--iface IFACE] [--dry-run] [--no-upgrade]"
      exit 0 ;;
    *) echo "Option inconnue: $1"; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;36m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*"; }

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "+ $*"
  else
    eval "$@"
  fi
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Exécute ce script avec sudo/root."
    exit 1
  fi
}

detect_iface() {
  if [[ -n "$IFACE" ]]; then
    log "Interface forcée via --iface: $IFACE"
    ip link show "$IFACE" >/dev/null 2>&1 || { err "Interface $IFACE introuvable"; exit 1; }
    return
  fi
  local candidates=(eth0 end0 enp0s25 enp1s0 enp2s0 enx* en*)
  for c in "${candidates[@]}"; do
    if ip link show "$c" >/dev/null 2>&1; then
      IFACE="$c"
      break
    fi
  done
  if [[ -z "$IFACE" ]]; then
    err "Aucune interface Ethernet détectée. Utilise --iface IFACE."
    exit 1
  fi
  log "Interface détectée: $IFACE"
}

ensure_nmcli() {
  if ! command -v nmcli >/dev/null 2>&1; then
    log "nmcli absent → installation de NetworkManager…"
    run "apt-get update -y"
    run "apt-get install -y network-manager"
    # Active NetworkManager si désactivé
    run "systemctl enable NetworkManager"
    run "systemctl restart NetworkManager"
  else
    log "nmcli présent."
  fi
}

apt_upgrade() {
  if [[ "$DO_UPGRADE" == "true" ]]; then
    log "Mise à jour du système (apt)…"
    run "apt-get update -y"
    run "DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade"
  else
    warn "Upgrade apt ignoré (--no-upgrade)."
  fi
}

resolve_ip_for_hostname() {
  local hn ip
  hn="$(hostname -s)"
  log "Hostname détecté: $hn"
  ip="${HOST_IP_MAP[$hn]:-}"
  if [[ -z "$ip" ]]; then
    err "Aucune IP définie pour l’hostname '$hn' dans HOST_IP_MAP."
    echo "→ Ajoute une entrée [${hn}]=\"10.10.0.X\" dans le script, ou force manuellement."
    exit 1
  fi
  echo "$ip"
}

nm_cleanup_old() {
  # Désactive/supprime les profils ethernet conflictuels (ex. Wired connection 1)
  if nmcli -t -f NAME,TYPE con show | grep -E ":ethernet$" >/dev/null 2>&1; then
    while IFS= read -r name; do
      [[ "$name" == "$CON_NAME" ]] && continue
      warn "Désactivation du profil ethernet existant: $name"
      run "nmcli con mod \"$name\" connection.autoconnect no || true"
      run "nmcli con down \"$name\" || true"
      # on peut aussi supprimer (idempotent)
      run "nmcli con delete \"$name\" || true"
    done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="ethernet"{print $1}')
  fi
}

nm_apply_static() {
  local ip="$1"
  log "Application IP statique: $ip$IP_PREFIX (GW $GATEWAY, DNS $DNS_PRIMARY $DNS_SECONDARY) sur $IFACE"
  # Si le profil existe, on modifie; sinon on crée
  if nmcli -t -f NAME con show | grep -Fx "$CON_NAME" >/dev/null 2>&1; then
    log "Profil $CON_NAME déjà présent → modification"
    run "nmcli con mod \"$CON_NAME\" \
      connection.id \"$CON_NAME\" \
      connection.autoconnect yes \
      ipv4.method manual \
      ipv4.addresses $ip$IP_PREFIX \
      ipv4.gateway $GATEWAY \
      ipv4.dns \"$DNS_PRIMARY $DNS_SECONDARY\" \
      ipv6.method ignore \
      2>/dev/null || true"
    run "nmcli con mod \"$CON_NAME\" connection.interface-name \"$IFACE\""
  else
    log "Création du profil $CON_NAME"
    run "nmcli con add type ethernet ifname \"$IFACE\" con-name \"$CON_NAME\" ip4 $ip$IP_PREFIX gw4 $GATEWAY"
    run "nmcli con mod \"$CON_NAME\" ipv4.dns \"$DNS_PRIMARY $DNS_SECONDARY\" ipv6.method ignore connection.autoconnect yes"
  fi

  # Active le profil
  run "nmcli con up \"$CON_NAME\""
}

quick_tests() {
  local ip="$1"
  echo
  log "=== TESTS DE CONNECTIVITÉ ==="
  run "ip -br a"
  run "ip route"
  echo
  log "Ping Gateway ($GATEWAY)…"
  run "ping -c3 -W2 $GATEWAY || true"
  log "Ping Internet (8.8.8.8)…"
  run "ping -c3 -W2 8.8.8.8 || true"
  log "Ping DNS (google.com)…"
  run "getent hosts google.com || true"
  echo
  log "Résumé: hostname=$(hostname -s) iface=$IFACE ip=$ip$IP_PREFIX gw=$GATEWAY dns=$DNS_PRIMARY,$DNS_SECONDARY"
}

main() {
  require_root
  detect_iface
  apt_upgrade
  ensure_nmcli

  local ip
  ip="$(resolve_ip_for_hostname)"

  nm_cleanup_old
  nm_apply_static "$ip"
  quick_tests "$ip"

  echo
  log "✅ Configuration réseau terminée pour $(hostname -s)."
  echo "   • IP: $ip$IP_PREFIX   GW: $GATEWAY   DNS: $DNS_PRIMARY,$DNS_SECONDARY"
  echo "   • Profil NM: $CON_NAME (interface: $IFACE)"
  echo
  echo "Next steps:"
  echo "  - Depuis ton Mac (VPN actif), teste: ping $ip ; ssh pi@$ip"
  echo "  - Une fois tous les nœuds configurés: docker swarm init/join"
}

main "$@"