#!/bin/bash

# Refixed and recoded by moni
#
# This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.
#
# Do's and Don'ts:
#   Do: Run this script in a controlled environment.
#   Do: Review the script's code before executing it.
#   Don't: Run this script on a production system during peak hours without prior approval.
#   Don't: Interrupt the script while it is running.

# User Agreement Prompt
echo ""
echo "This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages."
echo ""
read -p "Type 'AGREE' to continue: " agreement

if [ "$agreement" != "AGREE" ]; then
  echo "Agreement not provided. Exiting."
  exit 1
fi

# --- Initial Setup & OS Information ---

# Check for root privileges
# Purpose: Determine if the script is running with root privileges.
# Functionality: `id -u` returns the user ID. If it's 0, the user is root.
# Security Relevance: Many checks require root privileges to access system information.
if [ "$(id -u)" -ne 0 ]; then
  echo "This script requires root privileges. Please run with sudo." >&2
  exit 1
fi

# Determine the operating system and version
# Purpose: Identify the Linux distribution and version for accurate analysis.
# Functionality: `cat /etc/os-release` parses the OS release information file.  `grep` filters the output to extract the `NAME` and `VERSION`.
# Security Relevance: Different distributions and versions may have different vulnerabilities and configurations.
distro=$(cat /etc/os-release | grep '^NAME=' | cut -d'=' -f2 | tr -d '"')
version=$(cat /etc/os-release | grep '^VERSION=' | cut -d'=' -f2 | tr -d '"')
echo "Detected Distribution: $distro"
echo "Detected Version: $version"

# Create a temporary file to store the results
# Purpose: Store the output of the script in a temporary file.
# Functionality: `mktemp` creates a temporary file with a unique name.
# Security Relevance: This allows for later analysis and reporting.
tmp_file=$(mktemp /tmp/security_scan.XXXXXX)
echo "Results will be stored in: $tmp_file"

# --- Live System Analysis (Volatile Data Collection) ---

# Process & User Analysis
# Purpose: Identify running processes to detect suspicious or unauthorized activity.
# Functionality: `ps aux` lists all running processes with detailed information.  `tee` redirects the output to both the console and the temporary file.
# Security Relevance: Unusual processes can indicate malware or unauthorized software.
echo "[+] Running Processes:" | tee -a "$tmp_file"
ps aux | tee -a "$tmp_file"

# List logged-in users
# Purpose: Identify active user sessions.
# Functionality: `who` displays currently logged-in users.
# Security Relevance: Monitoring active users can help detect unauthorized access.
echo "
[+] Logged-in Users:" | tee -a "$tmp_file"
who | tee -a "$tmp_file"

# List loaded kernel modules
# Purpose: Identify loaded kernel modules that might be malicious or backdoors.
# Functionality: `lsmod` lists currently loaded kernel modules.
# Security Relevance: Rootkits often use kernel modules to hide their presence.
echo "
[+] Loaded Kernel Modules:" | tee -a "$tmp_file"
lsmod | tee -a "$tmp_file"

# Network Triage
# Purpose: Identify open network connections to detect suspicious communication.
# Functionality: `netstat -tulnp` displays listening and established TCP/UDP connections with process IDs. `ss -tulnp` provides similar information using the `ss` utility, often preferred for its speed.
# Security Relevance: Backdoors and malware often establish network connections.
echo "
[+] Active Network Connections (netstat):" | tee -a "$tmp_file"
netstat -tulnp | tee -a "$tmp_file"
echo "
[+] Active Network Connections (ss):" | tee -a "$tmp_file"
ss -tulnp | tee -a "$tmp_file"

# Identify processes with open ports
# Purpose: Determine which processes are listening on network ports.
# Functionality: `lsof -i -n` lists open internet and network files. `grep LISTEN` filters for listening ports.
# Security Relevance: Unauthorized processes listening on ports can indicate backdoors or malicious services.
echo "
[+] Processes with Open Ports:" | tee -a "$tmp_file"
lsof -i -n | grep LISTEN | tee -a "$tmp_file"

# --- Filesystem & Persistence Analysis ---

# Find recently modified files
# Purpose: Identify files that have been recently changed, potentially indicating malicious activity.
# Functionality: `find / -type f -mtime -1` searches for files modified within the last day.  `2>/dev/null` redirects error messages to avoid clutter.
# Security Relevance: Malware often modifies files to inject code or establish persistence.
echo "
[+] Recently Modified Files (last 24 hours):" | tee -a "$tmp_file"
find / -type f -mtime -1 2>/dev/null | tee -a "$tmp_file"

# Find SUID/SGID files
# Purpose: Identify files with SUID/SGID bits set, which can be exploited for privilege escalation.
# Functionality: `find / -perm -4000 -o -perm -2000` searches for files with SUID or SGID bits set. `ls -l` provides detailed information about the files.
# Security Relevance: Misconfigured SUID/SGID files can allow unauthorized users to execute commands with elevated privileges.
echo "
[+] SUID/SGID Files:" | tee -a "$tmp_file"
find / -perm -4000 -o -perm -2000 2>/dev/null -print0 | xargs -0 ls -l | tee -a "$tmp_file"

# Find world-writable files
# Purpose: Identify files that are writable by any user, which can be a security risk.
# Functionality: `find / -perm -0002` searches for world-writable files. `ls -l` provides detailed information about the files.
# Security Relevance: World-writable files can be modified by unauthorized users, potentially leading to system compromise.
echo "
[+] World-Writable Files:" | tee -a "$tmp_file"
find / -perm -0002 2>/dev/null -print0 | xargs -0 ls -l | tee -a "$tmp_file"

# Find suspicious hidden files and directories
# Purpose: Identify hidden files and directories that might be used by malware or rootkits.
# Functionality: `find / -path '*/\[.*]' -type f` searches for files starting with a dot ('.') recursively.  Excludes /proc, /sys, /dev, /run, /boot, /var/lib/docker, /var/lib/lxc from scanning
# Security Relevance: Malware often hides itself in hidden files and directories.
echo "
[+] Suspicious Hidden Files and Directories:" | tee -a "$tmp_file"
find / -path '/proc' -prune -o -path '/sys' -prune -o -path '/dev' -prune -o -path '/run' -prune -o -path '/boot' -prune -o -path '/var/lib/docker' -prune -o -path '/var/lib/lxc' -prune -o -name ".*" -print 2>/dev/null | tee -a "$tmp_file"

# Check for SSH backdoor - authorized_keys files with suspicious content
# Purpose: Check for backdoors in SSH configuration.
# Functionality: Searching for authorized_keys files and listing their content.
# Security Relevance: Detecting unauthorized access to SSH.
echo "
[+] Checking authorized_keys files for root access:" | tee -a "$tmp_file"
find /home/*/.ssh/authorized_keys -type f -print -exec cat {} \; 2>/dev/null | tee -a "$tmp_file"

# Check persistence mechanisms: cron jobs
# Purpose: Identify cron jobs that might be used to execute malicious scripts.
# Functionality: `ls -l /etc/cron*` lists cron job directories and files. `cat` displays the contents of cron files.
# Security Relevance: Malware often uses cron jobs to schedule malicious tasks.
echo "
[+] Cron Jobs:" | tee -a "$tmp_file"
ls -l /etc/cron* | tee -a "$tmp_file"
cat /etc/crontab | tee -a "$tmp_file"
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done | tee -a "$tmp_file"

# Check persistence mechanisms: systemd services and timers
# Purpose: Identify systemd services and timers that might be used to execute malicious services.
# Functionality: `systemctl list-unit-files --type=service,timer` lists enabled systemd services and timers.
# Security Relevance: Malware often uses systemd services to ensure persistence.
echo "
[+] Systemd Services and Timers:" | tee -a "$tmp_file"
systemctl list-unit-files --type=service,timer | tee -a "$tmp_file"

# --- Log & Account Analysis ---

# Analyze authentication logs
# Purpose: Identify failed login attempts or other suspicious authentication events.
# Functionality: `grep` searches for relevant keywords (e.g., 'Failed password', 'Invalid user') in authentication logs.
# Security Relevance: Failed login attempts can indicate brute-force attacks.
echo "
[+] Authentication Log Analysis:" | tee -a "$tmp_file"
grep -i 'Failed password' /var/log/auth.log /var/log/secure* 2>/dev/null | tee -a "$tmp_file"
grep -i 'Invalid user' /var/log/auth.log /var/log/secure* 2>/dev/null | tee -a "$tmp_file"
grep -i 'Accepted password' /var/log/auth.log /var/log/secure* 2>/dev/null | tee -a "$tmp_file"

# Check user command histories
# Purpose: Review user command histories for suspicious commands.
# Functionality: Iterate through user home directories and display the contents of `.bash_history` files.
# Security Relevance: Command histories can reveal malicious activity performed by users.
echo "
[+] User Command Histories:" | tee -a "$tmp_file"
for user in $(cut -f1 -d: /etc/passwd); do
  if [ -d "/home/$user" ]; then
    echo "
[+] History for user: $user" | tee -a "$tmp_file"
    cat /home/$user/.bash_history 2>/dev/null | tee -a "$tmp_file"
  fi
done

# Audit user/group accounts for anomalies (e.g., UID 0 users besides root)
# Purpose: Identify user accounts with UID 0 (root privileges) besides the root user.
# Functionality: `awk` filters `/etc/passwd` to find users with UID 0.
# Security Relevance: Unauthorized UID 0 accounts can compromise system security.
echo "
[+] Users with UID 0 (besides root):" | tee -a "$tmp_file"
awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v root | tee -a "$tmp_file"

# Check for accounts with empty passwords
# Purpose: Identify accounts that have no password set.
# Functionality: Utilizing `awk` to find accounts in `/etc/shadow` where the password field is empty.
# Security Relevance: Accounts without passwords pose a significant security risk.
echo "
[+] Checking accounts with empty passwords:" | tee -a "$tmp_file"
awk -F: '($2 == "") { print $1 }' /etc/shadow | tee -a "$tmp_file"

# Check for any other users having root access besides root user
# Purpose: Check for users having root access besides the root user.
# Functionality: To get the members of the `sudo` or `wheel` group that can execute commands with root access using `sudo`.
# Security Relevance: Detecting unauthorized privilege escalation.
echo "
[+] Checking for users with sudo access:" | tee -a "$tmp_file"
getent group sudo | cut -d: -f4 | tr ',', '\n' | grep -v '^$' | tee -a "$tmp_file"
getent group wheel | cut -d: -f4 | tr ',', '\n' | grep -v '^$' | tee -a "$tmp_file"

# --- Rootkit Detection ---

# Suggest running rootkit detection tools
# Purpose: Remind the user to run rootkit detection tools.
# Functionality: Prints instructions for running `rkhunter` and `chkrootkit`.
# Security Relevance: Rootkit detection tools can identify hidden malware that is difficult to detect manually.
echo "
[+] Rootkit Detection:"
echo "It is recommended to run rootkit detection tools such as rkhunter and chkrootkit." | tee -a "$tmp_file"
echo "  sudo apt-get install rkhunter chkrootkit"
echo "  sudo rkhunter --check"
echo "  sudo chkrootkit"


# --- After Scan Create a HTML page with result data ---

# Install necessary tools (if not already installed) for html creation using bash scripts. 
# Install hightlight is used for syntax highlighing. needs to be installed using apt or downloaded manually
#  sudo apt-get update && sudo apt-get install highlight

echo "[+] Generating HTML report..."

# HTML template using a robust theme
html_template='<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
            color: #333;
        }
        h1 {
            color: #4CAF50;
            text-align: center;
        }
        h2 {
            color: #555;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        .section {
            margin-bottom: 20px;
            background-color: #fff;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .log-output {
            background-color: #f9f9f9;
            padding: 10px;
            border: 1px solid #eee;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: monospace;
        }
        .highlighted {
            background-color: #ffffe0;
        }
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <div class="section">
        <h2>Scan Details</h2>
        <p><strong>Date:</strong> $(date)</p>
        <p><strong>System:</strong> $distro $version</p>
    </div>
    <div class="section">
        <h2>Scan Results</h2>
        $scan_results
    </div>
</body>
</html>'

# Generate HTML content from the temporary file
scan_results=""
while IFS= read -r line;
do
    if [[ "$line" == "[+]"* ]]; then
        scan_results+="<h2>${line:4}</h2>"
    else
        escaped_line=$(echo "$line" | sed 's/[&<>\"\']/\\&/g')
        scan_results+="<div class='log-output'>$(echo "$escaped_line" | highlight -O html)</div>"
    fi
done < "$tmp_file"

# Substitute variables in the HTML template
html_content=$(eval echo "$html_template")

# Write HTML content to a file
html_file="security_report.html"
echo "$html_content" > "$html_file"

echo "[+] HTML report generated: $html_file"


# Cleaning up temporary file
# Clean up the temporary file
# Purpose: Remove the temporary file.
# Functionality: `rm` removes the specified file.
# Security Relevance: Prevents sensitive information from being left on the system.
rm "$tmp_file"
echo "[+] Scan completed."
