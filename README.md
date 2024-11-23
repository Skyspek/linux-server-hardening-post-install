# Linux Server Hardening - Post Install

This script provides essential security measures to apply immediately after setting up a Linux server. It serves as a baseline to secure your environment and ensure best practices are implemented.

---

## **Features**

1. **Sudo User Creation**:
   - Adds or verifies a sudo user.
   - Automatically configures SSH keys.

2. **Custom SSH Port**:
   - Changes the default SSH port to enhance security (default: `2022`).

3. **SSH Configuration Hardening**:
   - Disables root login via SSH.
   - Disables password-based authentication.
   - Enables public key authentication only.

4. **Firewall Setup (UFW)**:
   - Allows only essential ports (SSH, HTTP, HTTPS).
   - Adds rate limiting for SSH connections to prevent brute-force attacks.
   - Blocks known malicious IP ranges.

5. **Network Hardening**:
   - Configures `sysctl` to protect against common network attacks (SYN floods, spoofing, etc.).

6. **Comprehensive Validation**:
   - Ensures the SSH service is running on the configured port.
   - Verifies that firewall rules are correctly applied.

---

## **Tested Environment**

- **Ubuntu 24.04 LTS**
- Compatible with other Ubuntu-based distributions, but minor adjustments might be needed.

---

## **Usage Instructions**

### **1. Clone the Repository**
   ```bash
   git clone https://github.com/skyspek/linux-server-hardening-post-install.git
   cd linux-server-hardening-post-install
   ```

### **2. Make the Script Executable**
   ```bash
   chmod +x server-hardening-post-install.sh
   ```

### **3. Run the Script**
   ```bash
   sudo ./server-hardening-post-install.sh
   ```

### **4. Restart the Server**
After running the script, restart your server to apply all settings:
   ```bash
   sudo reboot
   ```

Once the server restarts, ensure you connect using the **new SSH port** (default: `2022`).

---

## **Accessing SSH After Port Change**

1. Update your SSH client to use the new port. For example, if the port is `2022`:
   ```bash
   ssh -p 2022 username@your-server-ip
   ```

2. If you're using an SSH configuration file (`~/.ssh/config`), you can simplify this by adding:
   ```
   Host your-server
       HostName your-server-ip
       User your-username
       Port 2022
   ```

---

## **Optional: Install the Script for Global Use**

To make the script accessible globally from any directory:
1. Copy it to `/usr/local/bin/`:
   ```bash
   sudo cp server-hardening-post-install.sh /usr/local/bin/server-hardening-post-install
   ```
2. Make it executable:
   ```bash
   sudo chmod +x /usr/local/bin/server-hardening-post-install
   ```

Now, you can run it directly using:
   ```bash
   sudo server-hardening-post-install
   ```

---

## **Script Workflow**

1. **Sudo User Setup**: Prompts to create or verify a sudo user and configures their SSH keys.
2. **SSH Hardening**:
   - Changes the SSH port to a custom value.
   - Applies secure configurations to the SSH service.
3. **Firewall Rules**:
   - Configures UFW to allow only necessary services (SSH, HTTP, HTTPS).
   - Blocks a list of known malicious IPs.
4. **Network Settings**:
   - Enforces stricter kernel-level protections against spoofing, SYN floods, and other attacks.
5. **Validation**:
   - Ensures the SSH service is running on the new port.
   - Verifies that the firewall rules are active and correct.

---

## **Disclaimer**

This script provides a **baseline security configuration**. While it significantly improves server security, additional measures (like regular updates, monitoring, and backups) are necessary to ensure full protection.

- **Always review the script** before executing it.
- **Backup your data and configurations** beforehand.
- This script is provided **"as is"** without any warranty or liability.

## **License**

This project is licensed under the **[MIT License](https://github.com/Skyspek/linux-server-hardening-post-install/blob/main/LICENSE)**. For more details, see the [`LICENSE`](https://github.com/Skyspek/linux-server-hardening-post-install/blob/main/LICENSE) file.
