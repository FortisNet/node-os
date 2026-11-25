#!/bin/sh
# Test image only. Collects the facts that prove the base image on a cloud and
# writes them to /var/log/fortis-bootcheck.txt and to the console. It prints
# no secrets: key material is counted, user data is measured, not shown.
set -u
report=/var/log/fortis-bootcheck.txt
metadata=http://169.254.169.254/metadata/v1

result() { printf '%-22s %s\n' "$1" "$2"; }
check() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then result "$label" PASS; else result "$label" FAIL; fi
}
fetch() { wget -q -T 5 -O - "$1" 2>/dev/null; }

{
  echo '=== FortisNet bare tiny-cloud boot report ==='
  result generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Which image this is: the commit it was built from, and whether the
  # sources had uncommitted changes at the time.
  result image_commit "$(sed -n 's/^commit=//p' /etc/fortis-image 2>/dev/null)"
  result image_modified "$(sed -n 's/^modified=//p' /etc/fortis-image 2>/dev/null)"
  result image_built "$(sed -n 's/^built=//p' /etc/fortis-image 2>/dev/null)"
  result image_base "$(sed -n 's/^base=//p' /etc/fortis-image 2>/dev/null)"
  result kernel "$(uname -r)"
  result platform "$(tr -d '\n' </sys/class/dmi/id/sys_vendor 2>/dev/null) $(tr -d '\n' </sys/class/dmi/id/product_name 2>/dev/null)"
  result memory_kb "$(sed -n 's/^MemTotal: *\([0-9]*\).*/\1/p' /proc/meminfo)"
  result processors "$(grep -c '^processor' /proc/cpuinfo)"

  echo '--- network'
  address=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2 "=" $4}' | tr '\n' ' ')
  result ipv4_addresses "${address:-none}"
  result default_route "$(ip -4 route show default 2>/dev/null | head -n 1)"
  result nameservers "$(sed -n 's/^nameserver *//p' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
  check has_global_ipv4 sh -c 'ip -4 -o addr show scope global | grep -q .'
  check has_default_route sh -c 'ip -4 route show default | grep -q .'
  check dns_resolves nslookup dl-cdn.alpinelinux.org
  check outbound_http wget -q -T 10 --spider http://dl-cdn.alpinelinux.org/alpine/
  echo '--- interfaces file'
  sed 's/^/    /' /etc/network/interfaces 2>/dev/null

  # The first-boot tool detects the cloud and reads its metadata service
  # through one interface, whichever cloud this is.
  echo '--- cloud'
  result detected_cloud "$(cat /var/lib/cloud/.autodetect 2>/dev/null || echo unknown)"
  result cloud_hostname "$(imds @hostname 2>/dev/null)"
  result cloud_ssh_keys "$(imds @ssh-keys 2>/dev/null | grep -c .)"
  result cloud_user_data_bytes "$(imds @userdata 2>/dev/null | wc -c)"
  # DigitalOcean's own service, for extra detail there; empty elsewhere.
  echo '--- metadata (DigitalOcean only)'
  result metadata_route "$(ip -4 route get 169.254.169.254 2>/dev/null | head -n 1)"
  check metadata_http sh -c "wget -q -T 5 -O /dev/null $metadata/id"
  result droplet_id "$(fetch "$metadata/id")"
  result region "$(fetch "$metadata/region")"
  result public_ipv4 "$(fetch "$metadata/interfaces/public/0/ipv4/address")"
  result anchor_ipv4 "$(fetch "$metadata/interfaces/public/0/anchor_ipv4/address")"
  result reserved_ip_active "$(fetch "$metadata/reserved_ip/ipv4/active")"
  drive=$(blkid 2>/dev/null | grep -i 'LABEL="config-2"' | cut -d: -f1 | head -n 1)
  result config_drive "${drive:-absent}"

  echo '--- first boot'
  check cloud_autodetected sh -c '! grep -a "tiny-cloud/autodetect" /var/log/messages | grep -q "unable to determine cloud"'
  check imds_hostname sh -c 'imds @hostname | grep -q .'
  check imds_ssh_keys sh -c 'imds @ssh-keys | grep -q .'
  check bootstrap_complete test -e /var/lib/cloud/.bootstrap-complete
  keys=0
  [ -r /home/alpine/.ssh/authorized_keys ] && keys=$(grep -c . /home/alpine/.ssh/authorized_keys)
  result ssh_keys_installed "$keys"
  check ssh_listening sh -c 'netstat -ltn 2>/dev/null | grep -q ":22 "'
  # The image limits SSH to the operator's key. Ask the server itself what
  # it will enforce, and confirm the removed programs are really gone.
  effective=$(sshd -T 2>/dev/null)
  ssh_setting() { if printf '%s\n' "$effective" | grep -qi "^$2\$"; then result "$1" PASS; else result "$1" FAIL; fi; }
  ssh_setting ssh_config_valid 'port 22'
  ssh_setting ssh_no_passwords 'passwordauthentication no'
  ssh_setting ssh_no_keyboard_login 'kbdinteractiveauthentication no'
  ssh_setting ssh_no_root_login 'permitrootlogin no'
  ssh_setting ssh_key_only 'authenticationmethods publickey'
  ssh_setting ssh_no_forwarding 'allowtcpforwarding no'
  check unused_tools_absent sh -c '! command -v ssh && ! command -v sgdisk && ! command -v sftp-server'
  result packages_installed "$(apk info 2>/dev/null | wc -l)"
  # Files that differ from what the package database records. Packages were
  # removed by editing that database offline, so this is the proof that the
  # database and the disk still agree: it should be 0.
  audit=$(apk audit --system 2>/dev/null)
  result package_files_differing "$(printf '%s' "$audit" | grep -c .)"
  printf '%s\n' "$audit" | head -n 10 | sed 's/^/    /'
  if [ -e /var/lib/cloud/user-data ]; then
    result user_data_bytes "$(wc -c </var/lib/cloud/user-data)"
  else
    result user_data_bytes absent
  fi
  result hostname "$(hostname)"
  result root_filesystem "$(df -h / | awk 'NR==2 {print $2 " total, " $4 " free"}')"
  result block_devices "$(awk 'NR>2 && $4 !~ /[0-9]$/ {printf "%s=%dMiB ", $4, $3/1024}' /proc/partitions)"
  # The time service needs a few seconds after boot to agree with its
  # sources. Wait for it, and say how long it took: the orchestrator must
  # wait the same way before it checks a certificate or a signature date.
  waited=0
  until chronyc tracking 2>/dev/null | grep -q "Leap status *: Normal" || [ "$waited" -ge 90 ]; do
    sleep 3
    waited=$((waited + 3))
  done
  check clock_synchronised sh -c 'chronyc tracking 2>/dev/null | grep -q "Leap status *: Normal"'
  result clock_wait_seconds "$waited"

  # The node will run under crun with this isolation: the project's system
  # call filter, memory and task limits, no capabilities and a read-only
  # root. This test image installs crun from the network; the real image
  # carries it.
  echo '--- container runtime'
  result cgroup_filesystem "$(awk '$2 == "/sys/fs/cgroup" {print $3}' /proc/mounts)"
  result cgroup_controllers "$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
  if apk add --no-cache crun busybox-static >/dev/null 2>&1; then
    result crun_version "$(crun --version | head -n 1)"
    work=/run/fortis-bootcheck
    mkdir -p "$work/rootfs/bin" "$work/rootfs/proc" "$work/rootfs/dev" "$work/rootfs/tmp" "$work/rootfs/sys/fs/cgroup"
    cp /bin/busybox.static "$work/rootfs/bin/busybox"
    cp /etc/fortis-bootcheck-crun.json "$work/config.json"
    observed=$(crun --root "$work/state" run --bundle "$work" fortis-bootcheck 2>&1)
    printf '%s\n' "$observed" | sed 's/^/    /'
    expect() { if printf '%s\n' "$observed" | grep -q "$2"; then result "$1" PASS; else result "$1" FAIL; fi; }
    expect runs_unprivileged 'uid=10001 gid=10001'
    expect no_capabilities 'CapEff:.0000000000000000'
    expect no_new_privileges 'NoNewPrivs:.1'
    expect call_filter_active 'Seccomp:.2'
    expect memory_limit 'memory.max=536870912'
    expect task_limit 'pids.max=512'
    expect user_namespace_refused 'unshare.*not permitted'
    expect root_read_only 'Read-only file system'
  else
    result crun_install FAIL
  fi

  # The loaded set tells the real image builder which kernel modules a
  # Droplet needs, so the rest can be left out to shrink the image.
  echo '--- loaded kernel modules'
  lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort | tr '\n' ' ' | fold -s -w 76 | sed 's/^/    /'
  echo
  echo '--- tiny-cloud log (last 25 lines)'
  grep -i 'tiny-cloud' /var/log/messages 2>/dev/null | tail -n 25 | sed 's/^/    /'
  echo '=== end of report ==='
} >"$report" 2>&1
chmod 0644 "$report"
cat "$report" >/dev/console 2>/dev/null || true
