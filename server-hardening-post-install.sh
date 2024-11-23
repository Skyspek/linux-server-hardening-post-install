#!/bin/bash

# Script : server-hardening-post-install.sh
# Description : General-purpose server hardening script post-installation.
# Objective : Enhance security with simplicity, compatibility, and effectiveness.

LOG_FILE="/var/log/server_hardening_post_install.log"
SSH_PORT=2022  # Custom SSH port (change as needed)

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') : $1" | tee -a "$LOG_FILE"
}

### Step 1: Create or verify sudo user ###
create_sudo_user() {
    log "=== Step 1: Create or verify a sudo user ==="
    read -p "Enter the sudo user to create or verify: " sudo_user

    if id "$sudo_user" &>/dev/null; then
        log "User $sudo_user already exists."
    else
        log "Creating user $sudo_user..."
        sudo adduser "$sudo_user" || { log "Error: Failed to create user $sudo_user."; exit 1; }
        sudo usermod -aG sudo "$sudo_user" || { log "Error: Failed to add $sudo_user to sudo group."; exit 1; }
        log "User $sudo_user added to sudo group."
    fi

    # Configure SSH keys for the user
    log "Configuring SSH keys for $sudo_user..."
    sudo mkdir -p "/home/$sudo_user/.ssh" || { log "Error: Failed to create .ssh directory for $sudo_user."; exit 1; }
    sudo chmod 700 "/home/$sudo_user/.ssh"

    if [ -f /root/.ssh/authorized_keys ]; then
        sudo cp /root/.ssh/authorized_keys "/home/$sudo_user/.ssh/" || { log "Error: Failed to copy SSH keys."; exit 1; }
        log "Copied root's SSH keys to $sudo_user."
    else
        sudo touch "/home/$sudo_user/.ssh/authorized_keys" || { log "Error: Failed to create authorized_keys file."; exit 1; }
        log "Created authorized_keys file for $sudo_user."
    fi

    sudo chmod 600 "/home/$sudo_user/.ssh/authorized_keys"
    sudo chown -R "$sudo_user:$sudo_user" "/home/$sudo_user/.ssh"
    log "SSH configuration for $sudo_user completed."
}

### Step 2: Configure custom SSH port ###
configure_ssh() {
    log "=== Step 2: Configure SSH to use a custom port ==="
    if [ ! -d /etc/systemd/system/ssh.socket.d ]; then
        sudo mkdir -p /etc/systemd/system/ssh.socket.d || { log "Error: Failed to create SSH override directory."; exit 1; }
    fi

    cat << EOF | sudo tee /etc/systemd/system/ssh.socket.d/override.conf
[Socket]
ListenStream=
ListenStream=$SSH_PORT
EOF

    sudo systemctl daemon-reload || { log "Error: Failed to reload systemd daemon."; exit 1; }
    sudo systemctl restart ssh.socket || { log "Error: Failed to restart SSH socket."; exit 1; }

    if ss -tuln | grep -q ":$SSH_PORT"; then
        log "SSH is successfully configured to listen on port $SSH_PORT."
    else
        log "Error: SSH is not listening on the configured port $SSH_PORT."
        exit 1
    fi
}

### Step 2.1: Secure SSH configuration ###
secure_sshd() {
    log "=== Step 2.1: Securing SSH configuration ==="

    SSHD_CONFIG="/etc/ssh/sshd_config"

    if [ ! -f "${SSHD_CONFIG}.bak" ]; then
        sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak" || { log "Error: Failed to backup $SSHD_CONFIG."; exit 1; }
        log "Backup of $SSHD_CONFIG created: ${SSHD_CONFIG}.bak"
    fi

    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
    sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"

    sudo systemctl restart ssh || { log "Error: Failed to restart SSH service."; exit 1; }
    log "SSH service successfully restarted."
}

### Step 3: Configure UFW firewall ###
configure_ufw() {
    log "=== Step 3: Configure UFW Firewall ==="
    sudo apt-get install -y ufw >/dev/null 2>&1 || { log "Error: Failed to install UFW."; exit 1; }

    if ! sudo ufw status | grep -q "$SSH_PORT/tcp"; then
        sudo ufw allow "$SSH_PORT"/tcp || log "Error: Failed to allow SSH port $SSH_PORT."
    fi

    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw limit "$SSH_PORT"/tcp

    bad_ips=(
        # Censys
        "162.142.125.0/24" "167.94.138.0/24" "167.94.145.0/24" "167.94.146.0/24"
        "167.248.133.0/24" "199.45.154.0/24" "199.45.155.0/24" "206.168.34.0/24"
        "2602:80d:1000:b0cc:e::/80" "2620:96:e000:b0cc:e::/80"
        # Shodan
        "198.20.69.74" "198.20.70.114" "93.120.27.62" "71.6.135.131"
        "66.240.236.119" "82.221.105.6" "71.6.165.200" "71.6.146.185"
    )
    for ip in "${bad_ips[@]}"; do
        if ! sudo ufw status | grep -q "DENY.*from $ip"; then
            sudo ufw deny from "$ip" >/dev/null 2>&1 || log "Error: Failed to block $ip."
        else
            log "IP $ip is already blocked."
        fi
    done

    sudo ufw --force enable || { log "Error: Failed to enable UFW."; exit 1; }
    sudo ufw reload
    sudo ufw status verbose | tee -a "$LOG_FILE"
    log "UFW Firewall configuration completed."
}

### Step 4: Apply sysctl security settings ###
configure_sysctl() {
    log "=== Step 4: Apply sysctl security settings ==="
    cat << EOF | sudo tee /etc/sysctl.d/99-security.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
    sudo sysctl --system || { log "Error: Failed to apply sysctl settings."; exit 1; }
    log "Sysctl settings applied."
}

### Final checks ###
final_checks() {
    log "=== Final checks ==="
    ss -tuln | grep ":$SSH_PORT" || log "Error: SSH not listening on $SSH_PORT."
    sudo ufw status verbose | tee -a "$LOG_FILE"
    log "Final checks completed."
}

### Main execution ###
log "=== Starting server-hardening-post-install ==="
create_sudo_user
configure_ssh
secure_sshd
configure_ufw
configure_sysctl
final_checks
log "=== Server hardening completed ==="
