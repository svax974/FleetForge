#!/usr/bin/env bash
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
# probe_machine.sh — état OBSERVÉ d'une machine, en LECTURE SEULE. Envoyé sur l'entrée standard
# de ssh par probe_fleet.sh : aucune écriture, aucun redémarrage, aucun secret affiché.
# Les services de base (ssh, cron, docker…) sont filtrés de UNITS pour ne garder que l'applicatif.
echo "HOST=$(hostname) UP=$(uptime -p)"
echo "PORTS=$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -n | uniq | tr '\n' ' ')"
echo "NONLOOP=$(ss -ltnH 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\])/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -n | uniq | tr '\n' ' ')"
echo "DOCKER=$(docker ps --format '{{.Names}}({{.Image}})' 2>/dev/null | sed -E 's#(\(|/)[a-z0-9._-]+/#\1#' | tr '\n' ' ')"
echo "UNITS=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | grep -vE '^(systemd|dbus|getty|serial|ssh|cron|rsyslog|polkit|snapd|unattended|networkd|multipathd|chrony|ModemManager|udisks|user@|fwupd|packagekit|lvm|irqbalance|qemu|accounts|apparmor|ufw|fail2ban|containerd|docker|cloud|atd|lxcfs|open-vm|vgauth|rpc|nfs|haveged|kmod|plymouth|thermald|upower|wpa|bluetooth|avahi|colord|gdm|cups|ntp|time|resolved|apport|multipath|sysstat|auditd|firewalld|iscsid|mdmonitor|lxd|ubuntu|motd|e2scrub|blk|console|keyboard|logrotate|man-db|setvtrgb|dmesg|sshd|network|systemd-)' | sed 's/.service//' | tr '\n' ' ')"
echo "CRON=$(crontab -l 2>/dev/null | grep -vE '^#|^$' | awk '{print $1" "$2" "$3" "$4" "$5" "$6}' | cut -c1-90 | tr '\n' '|')"
echo "UFW=$(sudo ufw status 2>/dev/null | head -1)"
