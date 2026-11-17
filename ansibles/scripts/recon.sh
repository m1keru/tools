#!/usr/bin/env bash
# Read-only survey of a server before a node goes on it. It changes nothing,
# installs nothing and needs no root; with root it can also name the
# processes behind listening ports and read the firewall.
#
#   ssh USER@SERVER 'bash -s' < scripts/recon.sh
#   ssh USER@SERVER 'bash -s -- 443 8443' < scripts/recon.sh   # ports to check
#
# The output holds no secrets, but it does describe the host: keep it private.
set -u

have() { command -v "$1" >/dev/null 2>&1; }
row() { printf '%-18s %s\n' "$1" "$2"; }
section() { printf '\n== %s\n' "$1"; }

main() {
  local ports="$*"
  if [ -z "$ports" ]; then ports="443 8443"; fi

  section "system"
  local kver kmaj kmin
  kver="$(uname -r)"
  kmaj="${kver%%.*}"
  kmin="${kver#*.}"
  kmin="${kmin%%[!0-9]*}"
  row kernel "$kver"
  row arch "$(uname -m)"
  if [ -r /etc/os-release ]; then
    row os "$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
  elif [ -r /etc/redhat-release ]; then
    row os "$(cat /etc/redhat-release)"
  else
    row os unknown
  fi
  if [ -d /run/systemd/system ] && have systemctl; then
    row init "systemd $(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')"
  else
    row init "not systemd ($(ps -p 1 -o comm= 2>/dev/null || echo unknown))"
  fi
  row uptime "$(uptime 2>/dev/null | sed 's/^ *//')"
  row user "$(id -un) (uid $(id -u))"
  if have sudo; then row sudo present; else row sudo absent; fi

  section "can Xray run here"
  case "$kmaj$kmin" in
    '' | *[!0-9]*) row kernel-check "cannot parse $kver" ;;
    *)
      if [ "$kmaj" -gt 3 ] || { [ "$kmaj" -eq 3 ] && [ "$kmin" -ge 2 ]; }; then
        row go-runtime "ok (needs Linux 3.2+)"
      else
        row go-runtime "NO: kernel older than 3.2, Xray will not start"
      fi
      if [ "$kmaj" -gt 4 ] || { [ "$kmaj" -eq 4 ] && [ "$kmin" -ge 3 ]; }; then
        row low-ports "kernel ok for ports below 1024 (also needs systemd 229+)"
      else
        row low-ports "NO: use ports above 1024 on this host"
      fi
      ;;
  esac

  section "resources"
  # /proc/meminfo, not free(1): old procps prints "cached" in the column where
  # new ones print "available". MemAvailable itself needs Linux 3.14; before
  # it, count free + buffers + cache, less the shared memory inside "Cached".
  row memory "$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^(MemFree|Buffers|Cached):/{f+=$2} /^Shmem:/{f-=$2} END{if(a=="")a=f; printf "%d MB total, %d MB available", t/1024, a/1024}' /proc/meminfo)"
  row disk-root "$(df -Ph / | awk 'NR==2{print $4" free of "$2}')"
  if [ -d /opt ]; then row disk-opt "$(df -Ph /opt | awk 'NR==2{print $4" free of "$2}')"; fi
  row load "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"

  section "tools the installer needs"
  local t
  for t in curl unzip sha256sum ss netstat; do
    if have "$t"; then row "$t" present; else row "$t" absent; fi
  done
  if have curl; then
    # Old curl and OpenSSL builds cannot negotiate TLS with GitHub; then the
    # Xray archive has to be copied to the host and passed with --xray-zip.
    if curl -fsSI --max-time 10 -o /dev/null https://github.com/XTLS/Xray-core/releases 2>/dev/null; then
      row github reachable
    else
      row github "NOT reachable with this curl: use --xray-zip"
    fi
  fi

  section "listening ports"
  if have ss; then
    ss -ltnup 2>/dev/null | awk 'NR==1 || /LISTEN|UNCONN/' | cut -c1-150
  elif have netstat; then
    netstat -ltnup 2>/dev/null | cut -c1-150
  else
    echo "neither ss nor netstat is available"
  fi

  section "candidate ports"
  local p busy
  for p in $ports; do
    busy=free
    if have ss; then
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"; then busy="TCP IN USE"; fi
      if ss -lun 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"; then busy="$busy, UDP IN USE"; fi
    elif have netstat; then
      if netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"; then busy="TCP IN USE"; fi
      if netstat -lun 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"; then busy="$busy, UDP IN USE"; fi
    else
      busy=unknown
    fi
    row "port $p" "$busy"
  done

  section "firewall"
  if have ufw; then row ufw "$(ufw status 2>/dev/null | head -n1 || echo 'needs root')"; fi
  if have firewall-cmd; then row firewalld "$(firewall-cmd --state 2>&1 | head -n1)"; fi
  if have iptables; then
    local policy
    policy="$(iptables -S INPUT 2>/dev/null | head -n1)"
    if [ -n "$policy" ]; then
      row iptables "$policy, $(iptables -S INPUT 2>/dev/null | wc -l) INPUT rules"
    else
      row iptables "present (rules need root to read)"
    fi
  fi
  if have nft; then row nftables "$(nft list ruleset 2>/dev/null | grep -c '^table' || true) tables"; fi
  if have getenforce; then row selinux "$(getenforce 2>/dev/null)"; fi

  section "already installed"
  if [ -d /opt/obhod ]; then row obhod "present in /opt/obhod"; else row obhod absent; fi
  if [ -d /opt/ansibles ]; then row ansibles "present in /opt/ansibles"; else row ansibles absent; fi
  local s
  for s in xray x-ui 3x-ui sing-box hysteria nginx apache2 httpd docker postfix exim4 dovecot; do
    if have "$s" || { have systemctl && systemctl list-unit-files 2>/dev/null | grep -q "^$s\.service"; }; then
      row "$s" present
    fi
  done
  echo
}

main "$@"
