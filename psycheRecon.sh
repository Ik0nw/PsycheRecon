#!/usr/bin/env bash
set -Eeuo pipefail

# ────────────────────────────── Config ──────────────────────────────
OUTDIR_BASE="smartmap"
NCOL=${NCOL:-"$(tput cols 2>/dev/null || echo 100)"}
HTB_MODE=0
VERBOSE=""
WORDLIST_OVERRIDE=""
SCAN_UDP=0
UDP_MODE="top"
HTTP_PORTS_REGEX='(^|,)(80|443|8080|8000|8888|5000|3000|7001)(,|$)'
# Windows/AD probing ports
TLS_PROBE_PORTS_REGEX='(^|,)(443|636|3389|5986|8443)(,|$)'
WIN_HTTP_PORTS_REGEX='(^|,)(80|443|8080|8000|8888|5985|5986)(,|$)'

# Default wordlist (your choice)
WORDLIST_CANDIDATES=(
  "/usr/share/amass/wordlists/subdomains-top1mil-110000.txt"
)

# ────────────────────────────── Colors ──────────────────────────────
if [[ -t 1 ]]; then
  BRED=$'\033[1;31m'; BGRN=$'\033[1;32m'; BYEL=$'\033[1;33m'
  BBLU=$'\033[1;34m'; BCYN=$'\033[1;36m'; BOLD=$'\033[1m'
  DIM=$'\033[2m'; RST=$'\033[0m'
else
  BRED=""; BGRN=""; BYEL=""; BBLU=""; BCYN=""; BOLD=""; DIM=""; RST=""
fi

# ────────────────────────────── Helpers ─────────────────────────────
die(){ echo -e "${BRED}[!]${RST} $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing '$1' (apt update && apt install $1)"; }
hr(){ printf "%${NCOL}s\n" | tr ' ' '─'; }
box(){ hr; printf " %s%s%s\n" "$BOLD" "$1" "$RST"; hr; }

spinner(){ # spinner "msg" CMD...
  local pid msg; msg="$1"; shift
  ( "${@}" ) & pid=$!
  local marks='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
  printf "%s %s" "${BCYN}[~]${RST}" "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s %s %s" "${BCYN}[~]${RST}" "$msg" "${marks:i++%${#marks}:1}"
    sleep 0.12
  done
  wait "$pid" || true
  printf "\r%s %s %s\n" "${BGRN}[✓]${RST}" "$msg" "${DIM}(done)${RST}"
}

pretty_table(){ # stdin: "PORT\tSTATE\tSERVICE\tINFO"
  awk -F'\t' 'BEGIN{
    printf "%-8s %-7s %-12s %s\n","PORT","STATE","SERVICE","INFO";
    printf "%-8s %-7s %-12s %s\n","──────","──────","──────────","────";
  }{
    printf "%-8s %-7s %-12s %s\n",$1,$2,$3,$4
  }'
}

# VHost extraction from nmap normal output
extract_vhosts(){ # nmap normal output -> vhost hints (from redirect titles)
  awk '/http-title: /{sub(/.*http-title: /,""); print}' "$1" \
    | sed 's/.*redirect to http:\/\/\([^/]*\)\/.*/\1/;t;d' | sort -u
}

# Hosts backup (idempotent)
backup_hosts_once(){ # idempotent per run
  local stamp="$1"
  local bak="/etc/hosts.bak.${stamp}"
  [[ -f "$bak" ]] || cp -a /etc/hosts "$bak"
  echo -e "${DIM}Backup created: $bak${RST}"
}

# Add vhosts to /etc/hosts (merges existing entries for same IP)
add_vhosts_to_hosts(){
  local ip="$1" ; shift
  local stamp="$2" ; shift
  local -a vhosts=("$@")
  [[ ${#vhosts[@]} -gt 0 ]] || { echo -e "${BYEL}[!] No vhosts to add${RST}"; return 0; }
  backup_hosts_once "$stamp"

  local existing merged
  existing="$(awk -v ip="$ip" '
    $0 !~ /^[[:space:]]*#/ && $1 == ip {
      for(i=2;i<=NF;i++){ if($i ~ /^#/) break; print $i }
    }' /etc/hosts | sort -u
  )"

  merged="$(printf "%s\n%s\n" "$existing" "${vhosts[*]}" \
            | tr " " "\n" \
            | awk "NF{a[\$1]++}END{for(h in a)print h}" \
            | sort | xargs)"

  local tmp; tmp="$(mktemp)"
  awk -v ip="$ip" '
    $0 !~ /^[[:space:]]*#/ && $1 == ip {next}
    {print}
  ' /etc/hosts > "$tmp"

  printf "%s %s  # smartmap %s\n" "$ip" "$merged" "$stamp" >> "$tmp"

  if cat "$tmp" > /etc/hosts 2>/dev/null; then
    :
  else
    echo -e "${BYEL}[!] Overwrite blocked; appending merged line as fallback.${RST}"
    printf "%s %s  # smartmap %s\n" "$ip" "$merged" "$stamp" | tee -a /etc/hosts >/dev/null
  fi
  rm -f "$tmp"

  hr
  echo -e "${BOLD}${BCYN} 🔑  /etc/hosts UPDATED for ${ip}${RST}"
  hr
  for h in $merged; do
    echo -e "  ${BGRN}•${RST} $h"
  done
  hr

  if [[ -n "${VERBOSE}" ]]; then
    echo -e "${DIM}Full line:${RST}"
    printf "%s %s  # smartmap %s\n" "$ip" "$merged" "$stamp"
    echo
  fi
}

pick_wordlist(){
  if [[ -n "$WORDLIST_OVERRIDE" ]]; then
    [[ -f "$WORDLIST_OVERRIDE" ]] || die "Wordlist not found: $WORDLIST_OVERRIDE"
    echo "$WORDLIST_OVERRIDE"; return 0
  fi
  if [[ -f "${WORDLIST_CANDIDATES[0]}" ]]; then
    echo "${WORDLIST_CANDIDATES[0]}"
  else
    die "Default wordlist missing: ${WORDLIST_CANDIDATES[0]}. Use --wordlist <file>."
  fi
}

# baseline size for ffuf filtering
baseline_size(){ # size of a nonexistent vhost’s response
  local ip="$1" base="$2" proto="$3"
  local url="${proto}://${ip}/"
  curl -s -m 5 -H "Host: nonexist-${RANDOM}.${base}" "$url" | wc -c
}

ffuf_vhost_enum(){
  local ip="$1" base="$2" port="$3" out="$4"
  local proto="http"; [[ "$port" == "443" ]] && proto="https"
  local wl; wl="$(pick_wordlist)"
  local fs=""; command -v curl >/dev/null 2>&1 && fs="$(baseline_size "$ip" "$base" "$proto" || echo "")"
  local fs_arg=(); [[ -n "$fs" && "$fs" -gt 0 ]] && fs_arg=(-fs "$fs")
  ffuf -u "${proto}://$ip/" -H "Host: FUZZ.${base}" -w "$wl" \
       -mc 200,204,301,302,307,308,401,403 -fc 429 -t 80 -timeout 5 \
       "${fs_arg[@]}" -of csv -o "$out.csv" >/dev/null 2>&1 || true
  if [[ -s "$out.csv" ]]; then
    awk -F',' 'NR>1{print $1}' "$out.csv" | sed 's/^"//;s/"$//' | sort -u > "$out.txt"
  fi
}

gobuster_vhost_enum(){
  local ip="$1" base="$2" port="$3" out="$4"
  local proto="http"; [[ "$port" == "443" ]] && proto="https"
  local wl; wl="$(pick_wordlist)"
  gobuster vhost -u "${proto}://$ip" -w "$wl" -t 80 -k \
    -o "$out.gobuster" >/dev/null 2>&1 || true
  if [[ -s "$out.gobuster" ]]; then
    sed -n 's/^Found: \([^ ]*\).*/\1/p' "$out.gobuster" | grep -F ".${base}" | sort -u > "$out.txt"
  fi
}

do_subdomain_enum(){
  local ip="$1" base="$2" http_ports_csv="$3"
  local first_http_port
  first_http_port="$(echo "$http_ports_csv" | tr ',' '\n' | grep -E '^(80|443|8080|8000|8888|5000|3000|7001)$' | head -n1)"
  [[ -n "$first_http_port" ]] || return 0
  local OUT_SUBS="${OUTDIR}/subs-${base}"
  box "Subdomain / VHost Enumeration (${base})"
  echo -e "${DIM}Wordlist: $(pick_wordlist)${RST}"
  echo -e "${DIM}Using port ${first_http_port} for Host-header bruteforce against ${ip}${RST}"
  if command -v ffuf >/dev/null 2>&1; then
    spinner "ffuf vhost fuzzing (Host: FUZZ.${base})" ffuf_vhost_enum "$ip" "$base" "$first_http_port" "$OUT_SUBS"
  elif command -v gobuster >/dev/null 2>&1; then
    spinner "gobuster vhost (Host: FUZZ.${base})" gobuster_vhost_enum "$ip" "$base" "$first_http_port" "$OUT_SUBS"
  else
    echo -e "${BYEL}[!] Neither ffuf nor gobuster found. Install one:${RST}"
    echo "    apt update && apt install ffuf   # or: apt install gobuster"
    return 0
  fi
  if [[ -s "${OUT_SUBS}.txt" ]]; then
    echo -e "${BGRN}[+] Potential subdomains:${RST}"
    sed 's/^/  • /' "${OUT_SUBS}.txt"
    echo
    if (( HTB_MODE == 1 )); then
      [[ $EUID -eq 0 ]] || die "--htb mode requires root. Re-run with sudo."
      mapfile -t NEW_SUBS < "${OUT_SUBS}.txt"
      add_vhosts_to_hosts "$TARGET" "$STAMP" "${NEW_SUBS[@]}"
      echo
    else
      local joined; joined="$(tr '\n' ' ' < "${OUT_SUBS}.txt" | xargs)"
      echo -e "${DIM}Tip: printf '%s\n' \"$TARGET $joined\" | sudo tee -a /etc/hosts${RST}"
      echo
    fi
  else
    echo -e "${BYEL}[!] No interesting subdomains found.${RST}"
    echo -e "${DIM}Try a bigger/different list or adjust ffuf filters.${RST}"
    echo
  fi
}

dn_to_dns(){ sed -E 's/[[:space:]]//g; s/DC=//Ig; s/,DC=/./Ig; s/,.*$//' <<<"$1"; }

extract_tls_names(){
  local ip="$1" port="$2"
  local cert subject san
  cert="$(echo | openssl s_client -connect "${ip}:${port}" -servername "$ip" -showcerts 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null)" || return 0
  subject="$(sed -n 's/^subject= *//p' <<<"$cert" | sed -n 's#.*CN=##p' | awk -F'/' '{print $1}' )"
  san="$(sed -n 's/^X509v3 Subject Alternative Name: *//,/^$/p' <<<"$cert" | grep -Eo 'DNS:[^,]+' | cut -d: -f2)"
  printf '%s\n' "$subject" $san | awk 'NF' | sort -u
}

parse_smb_hostnames(){ awk '
  /Computer name:/  {c=$0; sub(/.*Computer name:[[:space:]]*/,"",c); print c}
  /FQDN:/           {f=$0; sub(/.*FQDN:[[:space:]]*/,"",f); print f}
  /Domain name:/    {d=$0; sub(/.*Domain name:[[:space:]]*/,"",d); print d}
' | awk 'NF' | sort -u; }

parse_http_ntlm_info(){ awk '
  /NetBIOS computer name:/ {c=$0; sub(/.*NetBIOS computer name:[[:space:]]*/,"",c); print c}
  /NetBIOS domain name:/   {d=$0; sub(/.*NetBIOS domain name:[[:space:]]*/,"",d); print d}
  /DNS domain:/            {e=$0; sub(/.*DNS domain:[[:space:]]*/,"",e); print e}
  /FQDN:/                  {f=$0; sub(/.*FQDN:[[:space:]]*/,"",f); print f}
' | awk 'NF' | sort -u; }

discover_windows_hostnames(){
  local ip="$1" open_ports_csv="$2" outdir="$3"
  local hits_file="${outdir}/win-hosts.txt"
  : > "$hits_file"

  if [[ "$open_ports_csv," =~ (^|,)445(,|$) ]]; then
    local smb_out="${outdir}/smb-os.nmap"
    nmap -Pn -n -p445 --script smb-os-discovery "$ip" -oN "$smb_out" >/dev/null 2>&1 || true
    parse_smb_hostnames < "$smb_out" >> "$hits_file"
  fi

  if [[ "$open_ports_csv," =~ (^|,)389(,|$) ]]; then
    local ldap_out="${outdir}/ldap-rootdse-389.nmap"
    nmap -Pn -n -p389 --script ldap-rootdse "$ip" -oN "$ldap_out" >/dev/null 2>&1 || true
    awk -F': ' '/defaultNamingContext:/ {print $2}' "$ldap_out" | while read -r dn; do dn_to_dns "$dn"; done >> "$hits_file"
  fi
  if [[ "$open_ports_csv," =~ (^|,)636(,|$) ]]; then
    local ldaps_out="${outdir}/ldap-rootdse-636.nmap"
    nmap -Pn -n -p636 --script ldap-rootdse "$ip" -oN "$ldaps_out" >/dev/null 2>&1 || true
    awk -F': ' '/defaultNamingContext:/ {print $2}' "$ldaps_out" | while read -r dn; do dn_to_dns "$dn"; done >> "$hits_file"
  fi

  if [[ "$open_ports_csv," =~ $WIN_HTTP_PORTS_REGEX ]]; then
    local http_ports; http_ports="$(echo "$open_ports_csv" | tr ',' '\n' | grep -E '^(80|443|8080|8000|8888|5985|5986)$' | paste -sd, -)"
    if [[ -n "$http_ports" ]]; then
      local ntlm_out="${outdir}/http-ntlm-info.nmap"
      nmap -Pn -n -p "$http_ports" --script http-ntlm-info "$ip" -oN "$ntlm_out" >/dev/null 2>&1 || true
      parse_http_ntlm_info < "$ntlm_out" >> "$hits_file"
    fi
  fi

  if [[ "$open_ports_csv," =~ $TLS_PROBE_PORTS_REGEX ]]; then
    local tls_ports; tls_ports="$(echo "$open_ports_csv" | tr ',' '\n' | grep -E '^(443|636|3389|5986|8443)$')"
    while read -r p; do
      [[ -n "$p" ]] || continue
      extract_tls_names "$ip" "$p" >> "$hits_file"
    done <<< "$tls_ports"
  fi

  awk '
    function ishost(s) { return ( s ~ /^[A-Za-z0-9._-]+$/ && length(s) > 1 ) }
    { gsub(/[[:space:]]+/,"",""); if(ishost($0)) print tolower($0) }
  ' "$hits_file" | sort -u > "${hits_file}.uniq" || true

  if [[ -s "${hits_file}.uniq" ]]; then
    echo "${hits_file}.uniq"
  fi
}

# ─────────────────────────────── Args ────────────────────────────────
usage(){
  cat <<EOF
Usage: $0 [--htb] [--verbose] [--wordlist <file>] [--udp|--udp-full] <target>

Options:
  --htb                 Auto-merge detected vhosts & Windows hostnames into /etc/hosts (requires sudo/root).
  --verbose             Print the full hosts line written to /etc/hosts.
  --wordlist <file>     Override default wordlist (${WORDLIST_CANDIDATES[0]}).
  --udp                 Perform a fast UDP discovery on top ports and focused UDP service scan (requires sudo).
  --udp-full            Scan ALL UDP ports (1–65535) before focused service scan (very slow; requires sudo).

Examples:
  $0 10.10.11.86
  sudo $0 --htb --udp 10.10.11.86
  $0 --wordlist /path/to/subs.txt --udp 10.10.11.86
EOF
  exit 1
}

ARGS=()
while (( $# )); do
  case "$1" in
    --htb) HTB_MODE=1; shift;;
    --verbose) VERBOSE=1; shift;;
    --wordlist) WORDLIST_OVERRIDE="${2:-}"; [[ -n "${WORDLIST_OVERRIDE}" ]] || usage; shift 2;;
    --udp) SCAN_UDP=1; UDP_MODE="top"; shift;;
    --udp-full) SCAN_UDP=1; UDP_MODE="full"; shift;;
    -h|--help) usage;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]:-}"
[[ $# -ge 1 ]] || usage
TARGET="$1"

# ──────────────────────────── Preconditions ─────────────────────────
need nmap; need awk; need sed; need grep
command -v curl >/dev/null 2>&1 || echo -e "${BYEL}[!] curl not found; ffuf size filtering may be less effective${RST}"
command -v openssl >/dev/null 2>&1 || echo -e "${BYEL}[!] openssl not found; TLS CN/SAN extraction will be skipped${RST}"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUTDIR="${OUTDIR_BASE}-${TARGET}-${STAMP}"
mkdir -p "$OUTDIR"

# ────────────────────────────── Header ──────────────────────────────
box "SmartMap — Focused Recon"
printf "%s Target           :%s %s\n" "$BBLU" "$RST" "$TARGET"
printf "%s Output directory :%s %s\n\n" "$BBLU" "$RST" "$OUTDIR"

# ─────────────────────── 1) Port Discovery (TCP) ────────────────────
box "[1/3] Discovering open TCP ports (1–65535)"
DISC_GREP="$OUTDIR/discover.grep"
discover_ports(){ nmap -n -Pn -p- --open -oG "$DISC_GREP" "$TARGET" >/dev/null; }
spinner "Sweeping all TCP ports" discover_ports

OPEN_PORTS=$(awk '/Ports: /{
  gsub(/\/open\/[^,]*/,"",$0);
  match($0,/Ports: (.*)/,m); gsub(/[^0-9,]/,"",m[1]); print m[1]
}' "$DISC_GREP" | sed 's/^,*//; s/,*$//' | tr -d ' ')

if [[ -z "$OPEN_PORTS" ]]; then
  echo -e "${BYEL}[!] No open TCP ports found${RST}"
else
  echo -e "${BGRN}[*] Open ports found :${RST} $OPEN_PORTS"; echo
fi

# ───────────── Optional UDP discovery (improved) ─────────────
if (( SCAN_UDP == 1 )); then
  box "[2] Discovering UDP ports"
  UDP_DISC_GREP="$OUTDIR/udp-discover.grep"

  discover_udp_ports(){
    if [[ $EUID -ne 0 ]]; then
      echo -e "${BYEL}[!] UDP scanning usually requires root. Re-run with sudo for best results.${RST}"
    fi

    # Tuned base flags to reduce retries and time spent per port
    local BASE_FLAGS=(-sU -Pn -n --open --defeat-icmp-ratelimit \
                      --max-retries 1 --initial-rtt-timeout 300ms --max-rtt-timeout 1500ms \
                      --min-rate 400 --host-timeout 10m)

    if [[ "$UDP_MODE" == "full" ]]; then
      # Full 1-65535 (very slow)
      nmap "${BASE_FLAGS[@]}" -p- -oG "$UDP_DISC_GREP" "$TARGET" >/dev/null 2>&1 || true
    else
      # Top-N UDP ports (practical)
      nmap "${BASE_FLAGS[@]}" --top-ports 200 -oG "$UDP_DISC_GREP" "$TARGET" >/dev/null 2>&1 || true
    fi
  }

  if [[ "$UDP_MODE" == "full" ]]; then
    spinner "Sweeping ALL UDP ports (1–65535)" discover_udp_ports
  else
    spinner "Sweeping top UDP ports (200)" discover_udp_ports
  fi

  OPEN_UDP_PORTS=$(awk '/Ports: /{ gsub(/\/open\/[^,]*/,"",$0); match($0,/Ports: (.*)/,m); gsub(/[^0-9,]/,"",m[1]); print m[1] }' "$UDP_DISC_GREP" 2>/dev/null | sed 's/^,*//; s/,*$//' | tr -d ' ' || true)

  if [[ -z "$OPEN_UDP_PORTS" ]]; then
    echo -e "${BYEL}[!] No open UDP ports found (or filtered).${RST}"
  else
    echo -e "${BGRN}[*] Open UDP ports found :${RST} $OPEN_UDP_PORTS"; echo
  fi
fi

# ───────────── 2/3) Targeted Scripts + Version on found TCP ports ─────────
box "[3/3] Targeted script + version scan (TCP)"
FOCUSED_PREFIX="$OUTDIR/focused"
focused_scan(){
  if [[ -n "$OPEN_PORTS" ]]; then
    nmap -sCV -Pn -n -p "$OPEN_PORTS" -oA "$FOCUSED_PREFIX" "$TARGET" >/dev/null 2>&1
  else
    :
  fi
}
spinner "Running nmap -sCV on discovered TCP ports" focused_scan
echo

# If UDP focused scan requested and we found UDP ports, run a focused UDP service/version scan
if (( SCAN_UDP == 1 )) && [[ -n "${OPEN_UDP_PORTS:-}" ]]; then
  box "Focused UDP service/version scan"
  UDP_FOCUS_PREFIX="$OUTDIR/udp-focused"
  focused_udp_scan(){
    nmap -sU -sV -Pn -n -p "$OPEN_UDP_PORTS" -oA "$UDP_FOCUS_PREFIX" "$TARGET" >/dev/null 2>&1 || true
  }
  spinner "Running nmap -sU -sV on discovered UDP ports" focused_udp_scan
  echo
fi

# ────────────────────────── Pretty Summary (TCP) ──────────────────────────
box "Summary (TCP)"
if [[ -f "$FOCUSED_PREFIX.nmap" ]]; then
  awk '
    /^PORT[ \t]/ {inports=1; next}
    inports && /^[0-9]+\/tcp/ {
      port=$1; state=$2; svc=$3;
      extra=$0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ */,"",extra);
      gsub(/\r/,"",extra); gsub(/[[:space:]]+$/,"",extra);
      printf "%s\t%s\t%s\t%s\n", port, state, svc, extra;
    }
  ' "$FOCUSED_PREFIX.nmap" | pretty_table
else
  echo -e "${DIM}No TCP-focused output available.${RST}"
fi
echo

# ────────────────────────── Pretty Summary (UDP) ──────────────────────────
if (( SCAN_UDP == 1 )); then
  box "Summary (UDP)"
  if [[ -f "$OUTDIR/udp-discover.grep" ]]; then
    awk '/Ports: /{ gsub(/\/open\/[^,]*/,"",$0); match($0,/Ports: (.*)/,m); gsub(/[^0-9,]/,"",m[1]); print m[1] }' "$OUTDIR/udp-discover.grep" | sed 's/^,*//; s/,*$//' | tr -d ' ' | awk '{ if(length($0)) print $0 }' | while read -r p; do
      echo -e "  • $p"
    done
  else
    echo -e "${DIM}No UDP-discovery output available.${RST}"
  fi

  if [[ -f "$OUTDIR/udp-focused.nmap" ]]; then
    echo
    awk '
      /^PORT[ \t]/ {inports=1; next}
      inports && /^[0-9]+\/udp/ {
        port=$1; state=$2; svc=$3;
        extra=$0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ */,"",extra);
        gsub(/\r/,"",extra); gsub(/[[:space:]]+$/,"",extra);
        printf "%s\t%s\t%s\t%s\n", port, state, svc, extra;
      }
    ' "$OUTDIR/udp-focused.nmap" | pretty_table
  fi
fi

# ───────────────────── Vhost hints & --htb mode ─────────────────────
VH_RAW=$(extract_vhosts "$FOCUSED_PREFIX.nmap" || true)
if [[ -n "$VH_RAW" ]]; then
  mapfile -t VH_ARR < <(printf '%s\n' "$VH_RAW")
  if (( HTB_MODE == 1 )); then
    [[ $EUID -eq 0 ]] || die "--htb mode requires root. Re-run with sudo."
    add_vhosts_to_hosts "$TARGET" "$STAMP" "${VH_ARR[@]}"
    echo
  else
    echo -e "${BOLD}Virtual host hint(s) detected:${RST}"
    printf '%s\n' "$VH_RAW" | sed 's/^/  • /'
    HOSTS_LINE="$TARGET $(echo "$VH_RAW" | tr '\n' ' ' | xargs)"
    echo -e "${DIM}Tip: printf '%s\n' \"$HOSTS_LINE\" | sudo tee -a /etc/hosts${RST}"
    echo
  fi
fi

# Auto subdomain/vhost enum when web open
if [[ "$OPEN_PORTS," =~ $HTTP_PORTS_REGEX ]] && [[ -n "$VH_RAW" ]]; then
  BASE_DOMAIN="$(printf '%s\n' "$VH_RAW" | head -n1)"
  do_subdomain_enum "$TARGET" "$BASE_DOMAIN" "$OPEN_PORTS"
fi

WIN_HOSTS_FILE="$(discover_windows_hostnames "$TARGET" "$OPEN_PORTS" "$OUTDIR" || true)"
if [[ -n "$WIN_HOSTS_FILE" && -s "$WIN_HOSTS_FILE" ]]; then
  box "Windows/AD Hostname Hints"
  echo -e "${BGRN}[+] Possible hostnames/domains discovered:${RST}"
  sed 's/^/  • /' "$WIN_HOSTS_FILE"
  echo

  SYNTH=()
  if [[ -n "$VH_RAW" ]]; then
    BASE_DOMAIN="$(printf '%s\n' "$VH_RAW" | head -n1)"
    while read -r h; do
      if [[ "$h" =~ ^[A-Za-z0-9_-]+$ ]]; then
        SYNTH+=( "${h}.${BASE_DOMAIN}" )
      fi
    done < "$WIN_HOSTS_FILE"
  fi

  mapfile -t WIN_CANDS < "$WIN_HOSTS_FILE"
  if [[ ${#SYNTH[@]} -gt 0 ]]; then
    WIN_CANDS=( $(printf "%s\n" "${WIN_CANDS[@]}" "${SYNTH[@]}" | awk 'NF{a[$1]++}END{for(h in a)print h}' | sort) )
  fi

  if (( HTB_MODE == 1 )); then
    [[ $EUID -eq 0 ]] || die "--htb mode requires root. Re-run with sudo."
    add_vhosts_to_hosts "$TARGET" "$STAMP" "${WIN_CANDS[@]}"
    echo
  else
    JOINED="$(printf "%s " "${WIN_CANDS[@]}" | xargs)"
    echo -e "${DIM}Tip: printf '%s\n' \"$TARGET $JOINED\" | sudo tee -a /etc/hosts${RST}"
    echo
  fi
fi

# Saved Outputs
box "Saved Outputs"
printf "  %s Discovery (greppable):%s %s\n" "$BCYN" "$RST" "$DISC_GREP"
printf "  %s Focused (normal)    :%s %s\n" "$BCYN" "$RST" "$FOCUSED_PREFIX.nmap"
printf "  %s Focused (grep)      :%s %s\n" "$BCYN" "$RST" "$FOCUSED_PREFIX.gnmap"
printf "  %s Focused (XML)       :%s %s\n" "$BCYN" "$RST" "$FOCUSED_PREFIX.xml"
if (( SCAN_UDP == 1 )); then
  printf "  %s UDP Discovery (grep):%s %s\n" "$BCYN" "$RST" "$OUTDIR/udp-discover.grep"
  printf "  %s UDP Focused (nmap)  :%s %s\n" "$BCYN" "$RST" "$OUTDIR/udp-focused.nmap"
fi
echo
echo -e "${BGRN}[✓] Done.${RST}"
