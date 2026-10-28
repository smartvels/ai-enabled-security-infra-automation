#!/bin/bash
# host-bootstrap-ansible.sh - the LAST manual step on a Proxmox VE / PBS host.
# After this, ctl-01 (10.10.1.10) manages the host with Ansible; people work only through the ops portal.
# Run once per host (GUI > node > Shell, as root):   bash host-bootstrap-ansible.sh
# Creates:  user 'ansible' (no password, key-only), ctl-01's key accepted ONLY from 10.10.1.10,
#           passwordless sudo for 'ansible' (logged), sshd rule: key-only for this user.
# Changes nothing else. Rollback: userdel -r ansible; rm /etc/sudoers.d/90-ansible /etc/ssh/sshd_config.d/90-ansible.conf
set -euo pipefail
CTL_IP="10.10.1.10"
PUBKEY='<PASTE THE ONE LINE FROM: cat ~/.ssh/ansible_ed25519.pub  ON ctl-01>'

[[ "$PUBKEY" =~ ^ssh-ed25519\ AAAA[0-9A-Za-z+/]+=*(\ .*)?$ ]] || { echo "STOP: paste ctl-01's ansible_ed25519.pub into PUBKEY first"; exit 1; }
command -v sudo >/dev/null || { apt-get update -qq && apt-get install -y -qq sudo; }

id ansible >/dev/null 2>&1 || useradd -m -s /bin/bash -c "ctl-01 automation" ansible
passwd -l ansible >/dev/null                       # no password login, ever
install -d -m 700 -o ansible -g ansible /home/ansible/.ssh
printf 'from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding %s\n' "$CTL_IP" "$PUBKEY" > /home/ansible/.ssh/authorized_keys
chown ansible:ansible /home/ansible/.ssh/authorized_keys; chmod 600 /home/ansible/.ssh/authorized_keys

cat > /etc/sudoers.d/90-ansible <<'EOF'
# ctl-01 automation (all actions are logged by sudo/journald and collected by Wazuh)
Defaults:ansible !requiretty
ansible ALL=(ALL:ALL) NOPASSWD: ALL
EOF
chmod 440 /etc/sudoers.d/90-ansible; visudo -cf /etc/sudoers.d/90-ansible >/dev/null

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/90-ansible.conf <<EOF
Match User ansible
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
EOF
grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
sshd -t && systemctl reload ssh

echo "=================================================================="
echo "host:         $(hostname)   ($(hostname -I | awk '{print $1}'))"
echo "ssh host key: $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"
echo "ansible user: ready (key-only, only from $CTL_IP, sudo)"
echo "=================================================================="
