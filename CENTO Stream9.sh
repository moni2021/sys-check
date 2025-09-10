#!/bin/bash
# Refixed and recoded by moni
#
# Disclaimer: This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.
#
# Do's and Don'ts:
#   Do: Run this script in a controlled environment.
#   Do: Review the script's code before executing it.
#   Don't: Run this script on a production system during peak hours without prior approval.
#   Don't: Interrupt the script while it is running.

# User Agreement Prompt
echo "\nDisclaimer: This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.\n"
read -p "Type 'AGREE' to continue: " agreement

if [ "$agreement" != "AGREE" ]; then
  echo "Agreement not provided. Exiting."
  exit 1
fi

# Initial Setup & OS Information

# Check for root privileges
# Purpose: Ensure the script is running with root privileges, which are required for many of the checks.
# Functionality: The `id -u` command returns the user ID. If it's 0, the user is root.
# Security Relevance: Many security checks require root privileges to access system files and processes.
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Exiting." 1>&2
  exit 1
fi

# Detect distribution and version
# Purpose: Identify the operating system and version to tailor the checks appropriately.
# Functionality: Uses `cat /etc/os-release` to get OS information and extracts the version ID.
# Security Relevance: Knowing the OS version is crucial for identifying relevant vulnerabilities.
OS_INFO=$(cat /etc/os-release)
OS_NAME=$(grep '^NAME=' <<< "$OS_INFO" | cut -d'=' -f2 | tr -d '"')
OS_VERSION=$(grep '^VERSION_ID=' <<< "$OS_INFO" | cut -d'=' -f2 | tr -d '"')
echo "Detected OS: $OS_NAME $OS_VERSION"

# Create a temporary file to store the results
# Purpose: Store the output of the script for later analysis and HTML report generation.
# Functionality: Uses `mktemp` to create a temporary file with a unique name.
# Security Relevance: Centralized logging facilitates analysis and reporting.
TEMP_FILE=$(mktemp /tmp/security_scan.XXXXXXXXXX)
echo "Results will be stored in: $TEMP_FILE"

# Live System Analysis (Volatile Data Collection)

# Process & User Analysis

# List running processes
# Purpose: Identify suspicious or unauthorized processes.
# Functionality: `ps aux` lists all running processes with detailed information.
# Security Relevance: Backdoors and malware often run as hidden processes.
echo "\n--- Running Processes ---" | tee -a "$TEMP_FILE"
ps aux | tee -a "$TEMP_FILE"

# List logged-in users
# Purpose: Identify unauthorized or unexpected user sessions.
# Functionality: `who` displays the currently logged-in users.
# Security Relevance: Unauthorized users may indicate a compromise.
echo "\n--- Logged-in Users ---" | tee -a "$TEMP_FILE"
who | tee -a "$TEMP_FILE"

# List loaded kernel modules
# Purpose: Identify suspicious or malicious kernel modules (rootkits).
# Functionality: `lsmod` lists loaded kernel modules.
# Security Relevance: Rootkits often use kernel modules to hide their presence.
echo "\n--- Loaded Kernel Modules ---" | tee -a "$TEMP_FILE"
lsmod | tee -a "$TEMP_FILE"

# Network Triage

# Show active network connections
# Purpose: Identify suspicious network connections, such as connections to unusual ports or IP addresses.
# Functionality: `netstat -tulnp` displays active TCP and UDP connections with process IDs and program names. `ss -tulnp` is similar and more modern.
# Security Relevance: Backdoors often establish network connections to communicate with attackers.
echo "\n--- Active Network Connections (netstat) ---" | tee -a "$TEMP_FILE"
netstat -tulnp | tee -a "$TEMP_FILE"
echo "\n--- Active Network Connections (ss) ---" | tee -a "$TEMP_FILE"
ss -tulnp | tee -a "$TEMP_FILE"

# Identify processes with open ports
# Purpose: Determine which processes are listening on network ports.
# Functionality: `lsof -i -P -n` lists open internet files (sockets) with process and port information.  `-i` selects network files, `-P` disables port name lookup, `-n` disables hostname lookup.
# Security Relevance: Unexpected processes listening on ports can indicate a backdoor.
echo "\n--- Processes with Open Ports ---" | tee -a "$TEMP_FILE"
lsof -i -P -n | tee -a "$TEMP_FILE"

# Filesystem & Persistence Analysis

# Find recently modified files
# Purpose: Identify files that may have been recently changed by an attacker.
# Functionality: `find / -mtime -1` finds files modified within the last day.  `-mtime -1` specifies the modification time in days.
# Security Relevance: Attackers often modify system files to install backdoors or hide their activity.
echo "\n--- Recently Modified Files (last 24 hours) ---" | tee -a "$TEMP_FILE"
find / -mtime -1 2>/dev/null | tee -a "$TEMP_FILE"

# Find SUID/SGID files
# Purpose: Identify files that run with elevated privileges.  Abuse of these files can lead to privilege escalation.
# Functionality: `find / -perm -4000 -o -perm -2000` finds files with SUID or SGID bits set. `-perm -4000` finds SUID files, `-perm -2000` finds SGID files.
# Security Relevance: Attackers can exploit SUID/SGID files to gain root access.
echo "\n--- SUID/SGID Files ---" | tee -a "$TEMP_FILE"
find / -perm -4000 -o -perm -2000 2>/dev/null | tee -a "$TEMP_FILE"

# Find world-writable files
# Purpose: Identify files that can be modified by any user.  This can be a security risk.
# Functionality: `find / -perm -2 -type f` finds world-writable regular files. `-perm -2` finds files with the world-writable bit set, `-type f` limits the search to regular files.
# Security Relevance: Attackers can use world-writable files to inject malicious code.
echo "\n--- World-Writable Files ---" | tee -a "$TEMP_FILE"
find / -perm -2 -type f 2>/dev/null | tee -a "$TEMP_FILE"

# Find suspicious hidden files
# Purpose: Identify hidden files that may be used to conceal malicious activity.
# Functionality: `find / -path '*/\[._]'` finds dot files and directories.
# Security Relevance: Attackers often hide their tools and configuration files.
echo "\n--- Suspicious Hidden Files ---" | tee -a "$TEMP_FILE"
find / -path '*/\.*' -type f 2>/dev/null | tee -a "$TEMP_FILE"

# Check persistence mechanisms

# Check cron jobs
# Purpose: Identify cron jobs that may be used to schedule malicious tasks.
# Functionality: Lists cron jobs for the current user (`crontab -l`) and checks cron directories (`/etc/cron.d`, `/etc/cron.daily`, etc.).
# Security Relevance: Attackers can use cron jobs to maintain persistence.
echo "\n--- Cron Jobs ---" | tee -a "$TEMP_FILE"
crontab -l 2>/dev/null | tee -a "$TEMP_FILE"
ls -l /etc/cron* 2>/dev/null | tee -a "$TEMP_FILE"
cat /etc/crontab 2>/dev/null | tee -a "$TEMP_FILE"

# Check systemd services and timers
# Purpose: Identify systemd services and timers that may be used to schedule malicious tasks.
# Functionality: `systemctl list-unit-files` lists all systemd unit files (services, timers, etc.).
# Security Relevance: Attackers can use systemd to maintain persistence.
echo "\n--- Systemd Services and Timers ---" | tee -a "$TEMP_FILE"
systemctl list-unit-files | tee -a "$TEMP_FILE"

# Check SSH keys
# Purpose: Identify unauthorized SSH keys that may be used to gain access to the system.
# Functionality: Checks the `authorized_keys` files in user home directories.
# Security Relevance: Attackers can add their SSH keys to gain persistent access.
echo "\n--- SSH Keys ---" | tee -a "$TEMP_FILE"
find /home/*/.ssh/authorized_keys -type f -print -exec cat {} \; 2>/dev/null | tee -a "$TEMP_FILE"

# Log & Account Analysis

# Analyze authentication logs
# Purpose: Identify failed login attempts or other suspicious activity in the authentication logs.
# Functionality: Uses `grep` to search for relevant keywords in the authentication logs (e.g., `/var/log/auth.log`, `/var/log/secure`).
# Security Relevance: Failed login attempts can indicate a brute-force attack.
echo "\n--- Authentication Logs ---" | tee -a "$TEMP_FILE"
grep -i "Failed password" /var/log/auth.log /var/log/secure 2>/dev/null | tee -a "$TEMP_FILE"
grep -i "Invalid user" /var/log/auth.log /var/log/secure 2>/dev/null | tee -a "$TEMP_FILE"

# Check user command histories
# Purpose: Review user command histories for suspicious commands.
# Functionality: Reads command history files (`~/.bash_history`, `~/.zsh_history`, etc.).
# Security Relevance: Attackers may leave traces of their activity in command histories.
echo "\n--- User Command Histories ---" | tee -a "$TEMP_FILE"
find /home/* -name .bash_history -o -name .zsh_history -o -name .history -type f -print -exec cat {} \; 2>/dev/null | tee -a "$TEMP_FILE"

# Audit user/group accounts for anomalies
# Purpose: Identify suspicious user accounts, such as users with UID 0 other than root.
# Functionality: Iterates through user accounts and checks their UIDs.
# Security Relevance: Attackers may create or modify user accounts to gain access.
echo "\n--- User Account Anomalies ---" | tee -a "$TEMP_FILE"
awk -F: '($3 == 0) { print $1 }' /etc/passwd | tee -a "$TEMP_FILE"

# Checking for possible backdoors beside root user backconnect
# Purpose: find any user with root access beside root user.
# Functionality: Reads /etc/passwd and checks for any UID of 0.
# Security Relevance: attacker could create a root user for backdoor access.
echo "\n--- Users with UID 0 (Root Privileges) ---" | tee -a "$TEMP_FILE"
awk -F: '($3 == 0) {print $1}' /etc/passwd  | tee -a "$TEMP_FILE"

# Rootkit Detection

# Check for rootkit hunters
# Purpose: Suggest the execution of known rootkit detection tools
# Functionality: Display command that the user can execute.
# Security Relevance: rootkit might not be detected with the other check made previously in this script.
echo "\n--- Rootkit Detection ---" | tee -a "$TEMP_FILE"
echo "Consider running rkhunter and chkrootkit for thorough rootkit detection:" | tee -a "$TEMP_FILE"
echo "sudo apt install rkhunter chkrootkit && sudo rkhunter --check && sudo chkrootkit" | tee -a "$TEMP_FILE"

# Generate HTML Report
# Purpose: Create a nicely formatted HTML report from the scan results.
# Functionality: Uses `cat`, `echo`, and `sed` to format the content of the temp file into an HTML file.
# Security Relevance: Facilitates easier analysis and sharing of scan results.

echo "\n--- Generating HTML Report ---"

REPORT_FILE="security_report.html"

# HTML Template with a simple theme
HTML_HEADER='<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Security Scan Report</title><style>body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; } h1 { color: #444; } pre { background-color: #eee; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }</style></head><body><h1>Security Scan Report</h1><pre>' 
HTML_FOOTER='</pre></body></html>'

echo "$HTML_HEADER" > "$REPORT_FILE"
sed 's/&/&amp;/g; s/</&lt;/g; s/>/&gt;/g' "$TEMP_FILE" >> "$REPORT_FILE"
echo "$HTML_FOOTER" >> "$REPORT_FILE"

echo "HTML report generated: $REPORT_FILE"

# Clean up temporary file
rm -f "$TEMP_FILE"
echo "Temporary file deleted."

echo "\nScan complete. Please review the report."

exit 0
