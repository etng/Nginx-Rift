#!/usr/bin/env bash
# Local conservative checker for Panelica article issues:
#   1) CVE-2026-42945 - NGINX ngx_http_rewrite_module
#   2) CVE-2026-46300 - Fragnesia kernel LPE exposure indicators
#
# No exploitation, no HTTP requests. Run as root/sudo for best results.

set -u
export LC_ALL=C

say() { printf '%-8s %s\n' "[$1]" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

ver_ge() {
  awk -v A="$1" -v B="$2" 'BEGIN{
    split(A,a,"."); split(B,b,".");
    for(i=1;i<=3;i++){
      ai=(a[i]==""?0:a[i])+0; bi=(b[i]==""?0:b[i])+0;
      if(ai>bi) exit 0; if(ai<bi) exit 1;
    }
    exit 0;
  }'
}
ver_lt() { ! ver_ge "$1" "$2"; }

nginx_version() {
  nginx -v 2>&1 | sed -nE 's/.*nginx\/([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1
}

package_mentions_cve() {
  if have dpkg-query; then
    zgrep -hisE 'CVE-2026-42945|42945|ngx_http_rewrite_module' \
      /usr/share/doc/nginx*/changelog* /usr/share/doc/libnginx*/changelog* 2>/dev/null | head -n5
  elif have rpm; then
    local bin pkg
    bin="$(command -v nginx 2>/dev/null || true)"
    [ -n "$bin" ] || return 1
    pkg="$(rpm -qf "$bin" 2>/dev/null || true)"
    [ -n "$pkg" ] && ! echo "$pkg" | grep -qi 'not owned' || return 1
    rpm -q --changelog "$pkg" 2>/dev/null | grep -Ei 'CVE-2026-42945|42945|ngx_http_rewrite_module' | head -n5
  fi
}

scan_rewrite_config() {
  # Emits HIGH lines for the core risky shape:
  # rewrite ... '?' ... '$1/$2/...' ; followed immediately by rewrite/if/set.
  awk '
  function trim(s){ gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
  function strip_comment(line, out, i, c, q, esc) {
    out=""; q=0; esc=0
    for(i=1;i<=length(line);i++){
      c=substr(line,i,1)
      if(esc){out=out c; esc=0; continue}
      if(c=="\\"){out=out c; esc=1; continue}
      if(c=="\"" && q!=39){q=(q==34?0:34); out=out c; continue}
      if(c=="\047" && q!=34){q=(q==39?0:39); out=out c; continue}
      if(c=="#" && q==0) break
      out=out c
    }
    return out
  }
  function follow(s){ return s ~ /^[[:space:]]*(rewrite|if|set)([[:space:];({]|$)/ }
  function is_rewrite(s){ return s ~ /^[[:space:]]*rewrite[[:space:]]+/ }
  function risky_rewrite(s){ return is_rewrite(s) && s ~ /\?/ && s ~ /\$[1-9][0-9]*/ }

  BEGIN{file="unknown"; buf=""; start=0; start_file="unknown"; prev=0; loose=0; high=0}
  /^[[:space:]]*nginx:/ {next}
  /^[[:space:]]*# configuration file / {
    file=$0; sub(/^[[:space:]]*# configuration file /,"",file); sub(/:[[:space:]]*$/,"",file); next
  }
  {
    clean=strip_comment($0)
    if(trim(clean)=="") next
    if(buf==""){start=NR; start_file=file}
    buf=buf " " clean
    if(clean ~ /[;{]/){
      stmt=trim(buf)
      if(prev && follow(stmt)){
        high++
        printf("HIGH\t%s:dump-line-%d: %s\n", prev_file, prev_line, prev_stmt)
        printf("    \tfollowed-by %s:dump-line-%d: %s\n", start_file, start, stmt)
      }
      if(risky_rewrite(stmt)){
        loose++; prev=1; prev_stmt=stmt; prev_line=start; prev_file=start_file
      } else {
        prev=0; prev_stmt=""; prev_line=0; prev_file="unknown"
      }
      buf=""; start=0; start_file=file
    }
  }
  END{
    if(high>0) printf("SUMMARY\thigh=%d loose=%d\n", high, loose)
    else if(loose>0) printf("SUMMARY\tloose=%d\n", loose)
    else print "SUMMARY\tnone"
  }' "$1"
}

module_state() {
  local m="$1" k="$(uname -r)"
  if [ -d "/sys/module/$m" ]; then echo "loaded_or_builtin"; return; fi
  if grep -qw "$m" "/lib/modules/$k/modules.builtin" 2>/dev/null; then echo "built_in"; return; fi
  if have modinfo && modinfo "$m" >/dev/null 2>&1; then echo "available_not_loaded"; return; fi
  echo "not_found"
}

modprobe_blocked() {
  local m="$1"
  grep -RhsE "^[[:space:]]*(install[[:space:]]+$m[[:space:]]+(/bin/false|/bin/true)|blacklist[[:space:]]+$m)" \
    /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null | head -n1
}

main() {
  echo "== Host =="
  [ -r /etc/os-release ] && . /etc/os-release && say INFO "OS: ${PRETTY_NAME:-unknown}"
  say INFO "Kernel: $(uname -r)"

  echo
  echo "== CVE-2026-42945 / NGINX rewrite module =="
  if ! have nginx; then
    say FAIL "nginx not found in PATH"
    exit 2
  fi

  local v version_status module_status dump out summary patched aslr verdict
  v="$(nginx_version)"
  say INFO "nginx -v: $(nginx -v 2>&1)"

  if [ -n "$v" ] && ver_ge "$v" "0.6.27" && ver_lt "$v" "1.30.1"; then
    version_status="affected_range"
    say WARN "Upstream version is in affected range: 0.6.27 through 1.30.0"
  elif [ -n "$v" ]; then
    version_status="fixed_or_outside_range"
    say OK "Upstream version is fixed/outside affected range"
  else
    version_status="unknown"
    say WARN "Could not parse nginx upstream version"
  fi

  if nginx -V 2>&1 | grep -q -- '--without-http_rewrite_module'; then
    module_status="disabled"
    say OK "ngx_http_rewrite_module appears disabled"
  else
    module_status="enabled_or_unknown"
    say WARN "ngx_http_rewrite_module appears enabled or not explicitly disabled"
  fi

  patched="$(package_mentions_cve || true)"
  if [ -n "$patched" ]; then
    say OK "Local package changelog mentions CVE/module; possible distro backport:"
    echo "$patched" | sed 's/^/         /'
  else
    say WARN "No local package changelog evidence for CVE-2026-42945; this does not prove unpatched"
  fi

  dump="$(mktemp -t nginx-T.XXXXXX)"
  if nginx -T >"$dump" 2>&1; then
    say INFO "nginx -T succeeded; scanning effective config"
    out="$(scan_rewrite_config "$dump")"
    echo "$out" | sed 's/^/         /'
    summary="$(echo "$out" | awk -F'\t' '/^SUMMARY/{print $2}' | tail -n1)"
  else
    say FAIL "nginx -T failed; run as root/sudo or fix config syntax"
    sed -n '1,20p' "$dump" | sed 's/^/         /'
    summary="unchecked"
  fi
  rm -f "$dump"

  if [ -r /proc/sys/kernel/randomize_va_space ]; then
    aslr="$(cat /proc/sys/kernel/randomize_va_space)"
    case "$aslr" in
      2) say OK "ASLR enabled: kernel.randomize_va_space=2" ;;
      1) say WARN "ASLR partially enabled: kernel.randomize_va_space=1" ;;
      0) say HIGH "ASLR disabled: kernel.randomize_va_space=0" ;;
      *) say WARN "Unknown ASLR value: $aslr" ;;
    esac
  fi

  echo
  if [ "$module_status" = "disabled" ]; then
    verdict="LIKELY_NOT_AFFECTED: rewrite module disabled"
  elif [ "$version_status" = "fixed_or_outside_range" ]; then
    verdict="LIKELY_NOT_AFFECTED: nginx upstream version fixed/outside range"
  elif echo "$summary" | grep -q '^high='; then
    verdict="LIKELY_AFFECTED: affected upstream range + rewrite module + matching config pattern"
  elif [ "$version_status" = "affected_range" ]; then
    verdict="POTENTIALLY_AFFECTED: affected upstream range, but no high-confidence config trigger found"
  else
    verdict="UNKNOWN"
  fi
  say VERDICT "$verdict"

  echo
  echo "== CVE-2026-46300 / Fragnesia kernel exposure indicators =="
  say INFO "This is not nginx-specific; it checks esp4/esp6/rxrpc module exposure only."
  local m st block exposed=0 blocked=0
  for m in esp4 esp6 rxrpc; do
    st="$(module_state "$m")"
    block="$(modprobe_blocked "$m" || true)"
    if [ -n "$block" ]; then
      blocked=1
      say OK "$m: $st; blocked by modprobe rule: $block"
    else
      case "$st" in
        loaded_or_builtin|built_in) exposed=1; say HIGH "$m: $st; no block rule" ;;
        available_not_loaded) exposed=1; say WARN "$m: available_not_loaded; no block rule" ;;
        not_found) say OK "$m: not_found" ;;
        *) say WARN "$m: $st" ;;
      esac
    fi
  done
  if [ "$exposed" -eq 1 ]; then
    say VERDICT "KERNEL_EXPOSURE_INDICATORS_PRESENT: patch/reboot or use vendor mitigation; do not disable esp4/esp6 blindly on IPsec hosts"
  elif [ "$blocked" -eq 1 ]; then
    say VERDICT "KERNEL_MITIGATION_INDICATORS_PRESENT: still install patched kernel when available"
  else
    say VERDICT "NO_OBVIOUS_KERNEL_MODULE_EXPOSURE_INDICATORS"
  fi
}

main "$@"
