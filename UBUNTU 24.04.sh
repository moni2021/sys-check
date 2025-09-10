#!/bin/bash
# Refixed and recoded by moni
# Disclaimer: This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.
#
# Do's and Don'ts:
# Do: Run this script in a controlled environment.
# Do: Review the script's code before executing it.
# Don't: Run this script on a production system during peak hours without prior approval.
# Don't: Interrupt the script while it is running.

# User Agreement Prompt
echo "\nDisclaimer: This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages." 
echo "\nPlease type 'AGREE' (case-sensitive) to continue:"
read agreement

if [ "$agreement" != "AGREE" ]; then
  echo "Agreement not provided. Exiting."
  exit 1
fi

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
  echo "This script requires root privileges. Please run as root or with sudo." 
  exit 1
fi

# Detect OS and Version
distro=$(lsb_release -si 2>/dev/null || cat /etc/os-release | grep -Po '(?<=NAME=").*?(?=")' 2>/dev/null || uname -s)
version=$(lsb_release -sr 2>/dev/null || cat /etc/os-release | grep -Po '(?<=VERSION=").*?(?=")' 2>/dev/null || uname -r)
echo "Detected Distribution: $distro"
echo "Detected Version: $version"

# Create a temporary file to store the results
tmp_file=$(mktemp /tmp/security_scan.XXXXXX)
echo "Results will be stored in: $tmp_file"

# Function to log results to the temporary file and screen
log_result() {
  echo "$1" | tee -a "$tmp_file"
}

# --- Live System Analysis ---
log_result "\n--- Live System Analysis ---"

# Process Analysis
log_result "\n--- Process Analysis ---"
# Purpose: List all running processes.
# Functionality: ps -ef lists all processes with full details including user, PID, PPID, and command.
# Security Relevance: Identifying unusual or unauthorized processes can indicate malicious activity.
log_result "Running Processes:"
ps -ef >> "$tmp_file"
ps -ef | tee -a "$tmp_file"

# User Analysis
log_result "\n--- User Analysis ---"
# Purpose: List currently logged-in users.
# Functionality: who displays information about currently logged-in users, including username, terminal, and login time.
# Security Relevance: Helps identify unauthorized or unexpected user logins.
log_result "Logged-in Users:"
who >> "$tmp_file"
who | tee -a "$tmp_file"

# Kernel Module Analysis
log_result "\n--- Kernel Module Analysis ---"
# Purpose: List loaded kernel modules.
# Functionality: lsmod displays the status of loaded kernel modules. This is important because rootkits often use kernel modules.
# Security Relevance: Detecting unknown or suspicious kernel modules can indicate a rootkit.
log_result "Loaded Kernel Modules:"
lsmod >> "$tmp_file"
lsmod | tee -a "$tmp_file"

# Network Connection Analysis
log_result "\n--- Network Connection Analysis ---"
# Purpose: Show active network connections.
# Functionality: netstat -tulnp displays all active TCP and UDP connections and listening ports, along with the PID and program name.
# Security Relevance: Identifying unauthorized or suspicious network connections or listening ports can indicate malware or backdoors.
log_result "Active Network Connections:"
netstat -tulnp >> "$tmp_file"
netstat -tulnp | tee -a "$tmp_file"

# Open Port Analysis
log_result "\n--- Open Port Analysis ---"
# Purpose: Identify processes with open ports.
# Functionality: lsof -i -P lists all open internet and network files, including ports, and their associated processes. -i specifies internet files, -P disables port name lookup for faster execution.
# Security Relevance: Helps pinpoint processes listening on unusual ports, potentially indicating malicious activity.
log_result "Processes with Open Ports:"
lsof -i -P >> "$tmp_file"
lsof -i -P | tee -a "$tmp_file"

# --- Filesystem and Persistence Analysis ---
log_result "\n--- Filesystem and Persistence Analysis ---"

# Recently Modified Files
log_result "\n--- Recently Modified Files ---"
# Purpose: Find recently modified files.
# Functionality: find / -type f -mtime -1 lists files modified in the last 24 hours. 2>/dev/null suppresses error messages.
# Security Relevance: Attackers often modify system files after gaining access.
log_result "Recently Modified Files (last 24 hours):"
find / -type f -mtime -1 2>/dev/null >> "$tmp_file"
find / -type f -mtime -1 2>/dev/null | tee -a "$tmp_file"

# SUID/SGID Files
log_result "\n--- SUID/SGID Files ---"
# Purpose: Find SUID/SGID files.
# Functionality: find / -perm /4000 -o -perm /2000 -type f lists files with SUID or SGID bits set. 2>/dev/null suppresses error messages.
# Security Relevance: SUID/SGID files can be exploited to gain elevated privileges. This check identifies potential privilege escalation vectors.
log_result "SUID/SGID Files:"
find / -perm /4000 -o -perm /2000 -type f 2>/dev/null >> "$tmp_file"
find / -perm /4000 -o -perm /2000 -type f 2>/dev/null | tee -a "$tmp_file"

# World-Writable Files
log_result "\n--- World-Writable Files ---"
# Purpose: Find world-writable files.
# Functionality: find / -perm -2 -type f lists files that are world-writable. 2>/dev/null suppresses error messages.
# Security Relevance: World-writable files can be modified by any user, posing a security risk.
log_result "World-Writable Files:"
find / -perm -2 -type f 2>/dev/null >> "$tmp_file"
find / -perm -2 -type f 2>/dev/null | tee -a "$tmp_file"

# Suspicious Hidden Files
log_result "\n--- Suspicious Hidden Files ---"
# Purpose: Find suspicious hidden files.
# Functionality: find / -path "*/.*" -type f -name ".*" -print lists all hidden files and directories.  It then filters using grep to look for common suspicious file extensions and filenames.
# Security Relevance: Attackers often hide malicious files by naming them with a leading dot. This check attempts to identify these files.
log_result "Suspicious Hidden Files:"
find / -path "*/.*" -type f -name ".*" 2>/dev/null >> "$tmp_file"
find / -path "*/.*" -type f -name ".*" 2>/dev/null | tee -a "$tmp_file"

# Cron Jobs
log_result "\n--- Cron Jobs ---"
# Purpose: Check cron jobs for persistence.
# Functionality: crontab -l lists the current user's cron jobs. cat /etc/crontab lists system-wide cron jobs. ls /etc/cron.* lists cron directories.
# Security Relevance: Cron jobs can be used to schedule malicious tasks.
log_result "User Cron Jobs:"
crontab -l 2>/dev/null >> "$tmp_file"
crontab -l 2>/dev/null | tee -a "$tmp_file"
log_result "System Cron Jobs:"
cat /etc/crontab 2>/dev/null >> "$tmp_file"
cat /etc/crontab 2>/dev/null | tee -a "$tmp_file"
log_result "Cron Directories:"
ls -l /etc/cron.* 2>/dev/null >> "$tmp_file"
ls -l /etc/cron.* 2>/dev/null | tee -a "$tmp_file"

# Systemd Services
log_result "\n--- Systemd Services ---"
# Purpose: Check systemd services for persistence.
# Functionality: systemctl list-unit-files --type=service lists all systemd service files.  Checking enabled services for suspicious entries.
# Security Relevance: Systemd services can be used to maintain persistence.
log_result "Systemd Service Files:"
systemctl list-unit-files --type=service 2>/dev/null >> "$tmp_file"
systemctl list-unit-files --type=service 2>/dev/null | tee -a "$tmp_file"

# Check SSH authorized_keys for backdoors
log_result "\n--- SSH Authorized Keys Check ---"
# Purpose: Check for unauthorized SSH keys.
# Functionality: Iterates through each user's home directory, checks if .ssh/authorized_keys exists, and lists its contents.
# Security Relevance: Attackers might add their own SSH keys to gain persistent access.
for user in $(cut -d: -f1 /etc/passwd); do
  home_dir=$(getent passwd $user | cut -d: -f6)
  if [ -d "$home_dir/.ssh" ]; then
    if [ -f "$home_dir/.ssh/authorized_keys" ]; then
      log_result "SSH authorized_keys for $user:"
      cat "$home_dir/.ssh/authorized_keys" >> "$tmp_file"
      cat "$home_dir/.ssh/authorized_keys" | tee -a "$tmp_file"
    fi
  fi
done

# --- Log and Account Analysis ---
log_result "\n--- Log and Account Analysis ---"

# Authentication Logs
log_result "\n--- Authentication Logs ---"
# Purpose: Analyze authentication logs.
# Functionality:  This will check /var/log/auth.log , /var/log/secure, and last command to check for any faield login attempts
# Security Relevance: Failed login attempts and successful logins from unusual locations can indicate brute-force attacks or compromised accounts.
log_result "Authentication Log (/var/log/auth.log):"
cat /var/log/auth.log 2>/dev/null | tail -n 200 >> "$tmp_file"
cat /var/log/auth.log 2>/dev/null | tail -n 200 | tee -a "$tmp_file"

log_result "Authentication Log (/var/log/secure):"
cat /var/log/secure 2>/dev/null | tail -n 200 >> "$tmp_file"
cat /var/log/secure 2>/dev/null | tail -n 200 | tee -a "$tmp_file"

log_result "Last Logins:"
last >> "$tmp_file"
last | tee -a "$tmp_file"


# User Command History
log_result "\n--- User Command History ---"
# Purpose: Check user command histories.
# Functionality: Iterates through each user's home directory and attempts to read their .bash_history file.
# Security Relevance: Command history can reveal suspicious commands or activities.
for user in $(cut -d: -f1 /etc/passwd); do
  home_dir=$(getent passwd $user | cut -d: -f6)
  if [ -f "$home_dir/.bash_history" ]; then
    log_result "Command History for $user:"
    cat "$home_dir/.bash_history" 2>/dev/null >> "$tmp_file"
    cat "$home_dir/.bash_history" 2>/dev/null | tee -a "$tmp_file"
  fi
done

# UID 0 Users (besides root)
log_result "\n--- UID 0 Users (besides root) ---"
# Purpose: Audit user accounts for anomalies, specifically looking for users with UID 0 other than root.
# Functionality:  This checks the UID of each user from /etc/passwd and checks if any user other than root has UID of 0
# Security Relevance: Users with UID 0 have root privileges, which is dangerous if unintended.
log_result "UID 0 Users (besides root):"
awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$' >> "$tmp_file"
awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$' | tee -a "$tmp_file"


# Check for users having root access beside root user
log_result "\n--- Checking For User With Root Access other than root ---"
getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | grep -v root  >> "$tmp_file"
getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | grep -v root | tee -a "$tmp_file"



# --- Rootkit Detection ---
log_result "\n--- Rootkit Detection ---"
# Purpose: Check for rootkits.
# Functionality: Recommends running rkhunter and chkrootkit, as this script does not automatically run them.
# Security Relevance: Rootkits hide malicious activity, making them difficult to detect.
log_result "Please consider running rkhunter (rkhunter --check) and chkrootkit for more thorough rootkit detection."

# --- Backdoor Detection --- #
log_result "\n--- Backdoor Detection ---"

# Check for listening ports associated with unusual processes (Backconnect Detection)
log_result "\n--- Checking for listening ports associated with unusual processes (Backconnect Detection) ---"
# Purpose: To Identify any process which can connect back to an attacker
# Functionality: Using netstat to list all ports with their PID and process Name.
# Security Relevance: To find and block any active session to malicious third party.
netstat -lnpt | awk '{print $4, $7}'  >> "$tmp_file"
netstat -lnpt | awk '{print $4, $7}' | tee -a "$tmp_file"


# Create HTML report
log_result "\n--- Creating HTML report ---"

cat <<EOF > /tmp/security_report.html
<!DOCTYPE html>
<html>
<head>
<title>Security Scan Report</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }
h1 { color: #4CAF50; text-align: center; }
h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
.container { width: 80%; margin: auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
.log-section { margin-bottom: 20px; }
pre { background-color: #eee; padding: 10px; overflow-x: auto; }
</style>
</head>
<body>
<div class="container">
<h1>Security Scan Report</h1>

EOF

sed -e 's/^/<h2>/g' -e 's/$/</h2><div class=
