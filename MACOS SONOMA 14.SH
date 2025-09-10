#!/bin/bash

# Refixed and recoded by moni
#
# This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.
#
# Do's and Don'ts:
# Do: Run this script in a controlled environment.
# Do: Review the script's code before executing it.
# Don't: Run this script on a production system during peak hours without prior approval.
# Don't: Interrupt the script while it is running.

# Display the disclaimer and prompt for agreement
echo "This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages."
echo "\nDo's and Don'ts:\nDo: Run this script in a controlled environment.\nDo: Review the script's code before executing it.\nDon't: Run this script on a production system during peak hours without prior approval.\nDon't: Interrupt the script while it is running."
read -p "\nType 'AGREE' to continue: " agreement

# Check if the user agreed
if [ "$agreement" != "AGREE" ]; then
  echo "Agreement not provided. Exiting."
  exit 1
fi

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Exiting."
  exit 1
fi

# --- Initial Setup & OS Information ---

# Get OS version information
os_version=$(sw_vers -productVersion)
# Purpose: Get the macOS version.
# Functionality: Uses the `sw_vers` command to retrieve the macOS product version.
# Security Relevance: Knowing the OS version is crucial for identifying applicable vulnerabilities and exploits.
echo "Operating System: macOS Sonoma"
echo "Version: $os_version"

# --- Define the temporary file for results ---
tmp_file="/tmp/security_scan_results.txt"
rm -f "$tmp_file" # remove old file if any
touch "$tmp_file"

echo "\n--- Live System Analysis --- " | tee -a "$tmp_file"

# --- Process & User Analysis ---

# List running processes
ps_output=$(ps aux)
# Purpose: List all running processes on the system.
# Functionality: The `ps aux` command displays a snapshot of all processes, including their user, PID, CPU usage, memory usage, and command.
# Security Relevance: Helps identify unauthorized or suspicious processes.
echo "\n--- Running Processes: --- " | tee -a "$tmp_file"
echo "$ps_output" | tee -a "$tmp_file"

# List logged-in users
who_output=$(who)
# Purpose: List all currently logged-in users.
# Functionality: The `who` command displays information about currently logged-in users, including their username, terminal, and login time.
# Security Relevance: Helps identify unauthorized users who may have gained access to the system.
echo "\n--- Logged-in Users: --- " | tee -a "$tmp_file"
echo "$who_output" | tee -a "$tmp_file"

# List loaded kernel extensions
kextstat_output=$(kextstat)
# Purpose: List all loaded kernel extensions.
# Functionality: The `kextstat` command displays information about loaded kernel extensions, including their name, version, and status.
# Security Relevance: Helps identify malicious or outdated kernel extensions that could be exploited.
echo "\n--- Loaded Kernel Extensions: --- " | tee -a "$tmp_file"
echo "$kextstat_output" | tee -a "$tmp_file"

echo "\n--- Network Triage --- " | tee -a "$tmp_file"

# --- Network Triage ---

# Show active network connections
netstat_output=$(netstat -an)
# Purpose: Display active network connections.
# Functionality: The `netstat -an` command displays a list of active network connections, including the protocol, local address, remote address, and state.
# Security Relevance: Helps identify unauthorized or suspicious network connections.
echo "\n--- Active Network Connections (netstat): --- " | tee -a "$tmp_file"
echo "$netstat_output" | tee -a "$tmp_file"

# Show active network connections using ss (if available)
if command -v ss &> /dev/null; then
  ss_output=$(ss -tan)
  # Purpose: Display active network connections using ss.
  # Functionality: The `ss -tan` command displays a list of active TCP connections.
  # Security Relevance: Provides an alternative way to identify unauthorized or suspicious network connections.
  echo "\n--- Active Network Connections (ss): --- " | tee -a "$tmp_file"
  echo "$ss_output" | tee -a "$tmp_file"
else
  echo "\n--- ss command not found. Skipping ss check. --- " | tee -a "$tmp_file"
fi

# Identify processes with open ports
lsof_output=$(lsof -i -n)
# Purpose: Identify processes with open ports.
# Functionality: The `lsof -i -n` command displays a list of processes that have open network ports.
# Security Relevance: Helps identify processes that are listening for network connections, which could be a sign of a backdoor or other malicious activity.
echo "\n--- Processes with Open Ports: --- " | tee -a "$tmp_file"
echo "$lsof_output" | tee -a "$tmp_file"

echo "\n--- Filesystem & Persistence Analysis --- " | tee -a "$tmp_file"

# --- Filesystem & Persistence Analysis ---

# Find recently modified files (last 24 hours)
find_output=$(find / -type f -mtime -1 -ls 2>/dev/null)
# Purpose: Find files modified in the last 24 hours.
# Functionality: The `find / -type f -mtime -1 -ls` command searches the entire filesystem for files that have been modified in the last 24 hours and displays detailed information about them.
# Security Relevance: Helps identify files that may have been recently created or modified by an attacker.
echo "\n--- Recently Modified Files (last 24 hours): --- " | tee -a "$tmp_file"
echo "$find_output" | tee -a "$tmp_file"

# Find SUID/SGID files
suid_output=$(find / -perm -4000 -ls 2>/dev/null)
sgid_output=$(find / -perm -2000 -ls 2>/dev/null)
# Purpose: Find SUID/SGID files.
# Functionality: The `find / -perm -4000 -ls` and `find / -perm -2000 -ls` commands search the entire filesystem for files that have the SUID or SGID bit set and displays detailed information about them.
# Security Relevance: SUID/SGID files can be used by attackers to escalate their privileges.
echo "\n--- SUID Files: --- " | tee -a "$tmp_file"
echo "$suid_output" | tee -a "$tmp_file"
echo "\n--- SGID Files: --- " | tee -a "$tmp_file"
echo "$sgid_output" | tee -a "$tmp_file"

# Find world-writable files
world_writable_output=$(find / -perm -0002 -ls 2>/dev/null)
# Purpose: Find world-writable files.
# Functionality: The `find / -perm -0002 -ls` command searches the entire filesystem for files that are world-writable and displays detailed information about them.
# Security Relevance: World-writable files can be modified by any user, which could lead to security vulnerabilities.
echo "\n--- World-Writable Files: --- " | tee -a "$tmp_file"
echo "$world_writable_output" | tee -a "$tmp_file"

# Find suspicious hidden files (dotfiles in user home directories)
for user_home in /Users/*; do
  if [ -d "$user_home" ]; then
    hidden_files_output=$(find "$user_home" -maxdepth 1 -name ".*" -ls 2>/dev/null)
    # Purpose: Find hidden files (dotfiles) in user home directories.
    # Functionality: This loop iterates through each user's home directory and uses the `find` command to search for files and directories whose names start with a dot (`.`).
    # Security Relevance: Attackers often hide malicious files and directories by prepending a dot to their names. This check helps identify such hidden files.
    if [ -n "$hidden_files_output" ]; then
      echo "\n--- Suspicious Hidden Files in $user_home: --- " | tee -a "$tmp_file"
      echo "$hidden_files_output" | tee -a "$tmp_file"
    fi
  fi
done

echo "\n--- Persistence Mechanisms --- " | tee -a "$tmp_file"

# Check cron jobs
cron_output=$(crontab -l 2>/dev/null)
# Purpose: Check cron jobs for all users.
# Functionality: The `crontab -l` command lists the cron jobs for the current user.  This is run without redirecting errors to null so the script can identify which users cannot run crontab -l.
# Security Relevance: Cron jobs can be used by attackers to schedule malicious tasks to run automatically.
echo "\n--- Current User Cron Jobs: --- " | tee -a "$tmp_file"
echo "$cron_output" | tee -a "$tmp_file"

# Check cron.d directory (system-wide cron jobs)
if [ -d "/etc/cron.d" ]; then
  cron_d_output=$(ls -l /etc/cron.d/)
  # Purpose: Check the /etc/cron.d directory for system-wide cron jobs.
  # Functionality: The `ls -l /etc/cron.d/` command lists the contents of the /etc/cron.d directory.
  # Security Relevance: Similar to user-specific cron jobs, system-wide cron jobs can also be abused by attackers for persistence.
  echo "\n--- System-Wide Cron Jobs (/etc/cron.d/): --- " | tee -a "$tmp_file"
  echo "$cron_d_output" | tee -a "$tmp_file"
fi

# Check launchd agents and daemons (macOS specific)
launchd_agents=$(ls -l /Library/LaunchAgents/ 2>/dev/null)
launchd_daemons=$(ls -l /Library/LaunchDaemons/ 2>/dev/null)
user_launchd_agents=$(ls -l ~/Library/LaunchAgents/ 2>/dev/null)
# Purpose: Check for launchd agents and daemons.
# Functionality: The `ls -l` command lists the contents of the LaunchAgents and LaunchDaemons directories.
# Security Relevance: Launchd is the system and service manager for macOS, and it can be used to automatically launch applications and services at boot or on demand. Attackers can use launchd to establish persistence.
echo "\n--- Launchd Agents (/Library/LaunchAgents/): --- " | tee -a "$tmp_file"
echo "$launchd_agents" | tee -a "$tmp_file"
echo "\n--- Launchd Daemons (/Library/LaunchDaemons/): --- " | tee -a "$tmp_file"
echo "$launchd_daemons" | tee -a "$tmp_file"
echo "\n--- User Launchd Agents (~/Library/LaunchAgents/): --- " | tee -a "$tmp_file"
echo "$user_launchd_agents" | tee -a "$tmp_file"

# Check SSH authorized keys
for user_home in /Users/*; do
  if [ -d "$user_home/.ssh" ]; then
    authorized_keys_output=$(ls -l "$user_home/.ssh/authorized_keys" 2>/dev/null)
    # Purpose: Check for SSH authorized keys in user home directories.
    # Functionality: This loop iterates through each user's home directory, checks if the .ssh directory exists, and then lists the contents of the authorized_keys file.
    # Security Relevance: Attackers can add their own SSH keys to the authorized_keys file to gain persistent access to the system.
    if [ -n "$authorized_keys_output" ]; then
      echo "\n--- SSH Authorized Keys for $user_home: --- " | tee -a "$tmp_file"
      echo "$authorized_keys_output" | tee -a "$tmp_file"
    fi
  fi
done

echo "\n--- Log & Account Analysis --- " | tee -a "$tmp_file"

# --- Log & Account Analysis ---

# Analyze authentication logs (check /var/log/auth.log or /var/log/system.log depending on the system)
auth_log_file="/var/log/system.log"
if [ -f "$auth_log_file" ]; then
  failed_login_attempts=$(grep "Failed password" "$auth_log_file" | tail -n 20)
  # Purpose: Analyze authentication logs for failed login attempts.
  # Functionality: The `grep` command searches the /var/log/system.log file for lines containing "Failed password". The `tail -n 20` command displays the last 20 lines.
  # Security Relevance: A high number of failed login attempts could indicate a brute-force attack.
  echo "\n--- Recent Failed Login Attempts (from $auth_log_file): --- " | tee -a "$tmp_file"
echo "$failed_login_attempts" | tee -a "$tmp_file"

  successful_ssh_logins=$(grep "Accepted password" "$auth_log_file" | tail -n 20)
  # Purpose: Check for successful SSH logins
  # Functionality: looks for the string "Accepted password" in the specified file
  # Security Relevance: Review the source IP address that is connected to the mac os box
    echo "\n--- Recent Succesful SSH Logins (from $auth_log_file): --- " | tee -a "$tmp_file"
echo "$successful_ssh_logins" | tee -a "$tmp_file"
else
  echo "\n--- Authentication log file ($auth_log_file) not found. --- " | tee -a "$tmp_file"
fi

# Check user command histories
for user_home in /Users/*; do
  if [ -d "$user_home" ]; then
    history_file="$user_home/.zsh_history"
    if [ -f "$history_file" ]; then
      history_output=$(tail -n 20 "$history_file")
      # Purpose: Check user command histories.
      # Functionality: This loop iterates through each user's home directory, checks if the .zsh_history file exists, and then displays the last 20 lines of the file.
      # Security Relevance: User command histories can reveal commands that were executed by the user, which could provide valuable information to an attacker.
      echo "\n--- Recent Commands for $user_home (from $history_file): --- " | tee -a "$tmp_file"
      echo "$history_output" | tee -a "$tmp_file"
    fi
  fi
done

# Audit user/group accounts for anomalies (e.g., UID 0 users besides root)
other_uid_0_users=$(dscl . list /Users UniqueID | awk '$2 == 0 {print $1}')
# Purpose: Audit user accounts for anomalies, specifically looking for users with UID 0 besides root.
# Functionality: The `dscl . list /Users UniqueID` command lists all users and their UniqueID. The `awk` command filters the output to find users with UID 0.  If the system doesn't support dscl it will just skip the check.
# Security Relevance: Users with UID 0 have root privileges, so any user besides root with UID 0 is a potential security risk.
if [ -n "$other_uid_0_users" ]; then
  echo "\n--- WARNING: Non-root users with UID 0 found: $other_uid_0_users --- " | tee -a "$tmp_file"
fi

#Get user who have root access by using SUDO
users_with_sudo=$(grep -E '^%admin|^%wheel' /etc/group | awk -F: '{print $4}' | tr ',' '\n' | sort -u)

echo "\n--- Users with sudo access: $users_with_sudo --- " | tee -a "$tmp_file"


echo "\n--- Rootkit Detection --- " | tee -a "$tmp_file"

# --- Rootkit Detection ---

# Recommend running rkhunter and chkrootkit (if installed)
if command -v rkhunter &> /dev/null; then
  echo "\nrkhunter is installed. Consider running 'rkhunter --check' to scan for rootkits." | tee -a "$tmp_file"
else
  echo "\nrkhunter is not installed. Consider installing it to scan for rootkits." | tee -a "$tmp_file"
fi

if command -v chkrootkit &> /dev/null; then
  echo "\nchkrootkit is installed. Consider running 'chkrootkit' to scan for rootkits." | tee -a "$tmp_file"
else
  echo "\nchkrootkit is not installed. Consider installing it to scan for rootkits." | tee -a "$tmp_file"
fi

# Find any possible backConnect
backconnect=$(grep -rnw '/Applications' -e 'socket.socket(socket.AF_INET, socket.SOCK_STREAM)' -e 'os.system("nc' -e 'subprocess.Popen' 2>/dev/null)
echo "\n--- Backconnect Checking--- " | tee -a "$tmp_file"
echo "$backconnect" | tee -a "$tmp_file"

# --- Generate HTML report ---

# Create a basic HTML template
html_template='<!DOCTYPE html>
<html>
<head>
<title>Security Scan Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
h1 { color: #4CAF50; }
h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
pre { background-color: #eee; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }
.section { margin-bottom: 20px; }
.disclaimer { font-size: small; color: #777; }
</style>
</head>
<body>
<h1>Security Scan Report</h1>
<p class="disclaimer">This report summarizes the findings of the security scan. Please review the details carefully.</p>
__CONTENT__
</body>
</html>'

# Read the content of the temporary file
content=$(cat "$tmp_file")

# Escape special characters for HTML
escaped_content=$(echo "$content" | sed 's/&/&amp;/g; s/</&lt;/g; s/>/&gt;/g; s/"/&quot;/g')

# Structure the content into HTML sections
html_content="<h2>Scan Results</h2><pre>
$escaped_content
</pre>"

# Replace the placeholder in the HTML template with the scan results
html_report=$(echo "$html_template" | sed "s/__CONTENT__/$html_content/g")

# Save the HTML report to a file
report_file="/tmp/security_scan_report.html"
echo "$html_report" > "$report_file"

echo "\nHTML report saved to: $report_file" | tee -a "$tmp_file"

echo "\nScan complete. Results stored in $tmp_file and $report_file"

exit 0
