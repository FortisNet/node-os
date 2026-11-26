#!/bin/sh
# Start command of the container packaging of the node host image. It does
# what the fortis-native service does on a machine: configure a new host
# once, then run the orchestrator's supervisor until the container stops.
#
# Settings are the container's FORTIS_* environment variables, used the first
# time only. Output goes to the container's log.
set -eu
# The node gets its own memory and process limits from control groups. A
# group that holds processes cannot hand its controllers down, and at start
# everything in the container is in its top group. So move what runs now into
# a group of its own and hand every controller down, as an init system does
# on a machine. Without the rights for this the orchestrator still starts and
# its log says the node could not be started.
groups=/sys/fs/cgroup
# Docker hands a container its control groups read-only unless it runs with
# --privileged. They are this container's own (--cgroupns private), so make
# them writable; that needs the SYS_ADMIN capability and nothing more.
if [ -f "$groups/cgroup.controllers" ] && ! mkdir -p "$groups/init" 2>/dev/null; then
  mount -o remount,rw "$groups" 2>/dev/null || true
fi
if [ -f "$groups/cgroup.controllers" ] && mkdir -p "$groups/init" 2>/dev/null; then
  while read -r process; do
    echo "$process" >"$groups/init/cgroup.procs" 2>/dev/null || true
  done <"$groups/cgroup.procs"
  # The file is one line of names: words are what is wanted.
  # shellcheck disable=SC2013
  for controller in $(cat "$groups/cgroup.controllers"); do
    echo "+$controller" >"$groups/cgroup.subtree_control" 2>/dev/null ||
      echo "Control group controller not available: $controller" >&2
  done
else
  echo 'Control groups cannot be prepared; start the container with the options in the README' >&2
fi
config=/etc/fortis/orchestrator.conf
if [ ! -e "$config" ] && [ ! -e /etc/fortis/first-boot.conf ]; then
  mkdir -p /etc/fortis
  (umask 077 && { env | grep '^FORTIS_' || true; } >/etc/fortis/first-boot.conf)
fi
/usr/libexec/fortis/native-controller "$config" first-boot
exec /usr/libexec/fortis/run-native-service.sh "$config"
