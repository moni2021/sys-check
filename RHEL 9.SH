#!/bin/bash

# Refixed and recoded by moni

# This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.
#
# Do's and Don'ts:
#   Do: Run this script in a controlled environment.
#   Do: Review the script's code before executing it.
#   Don't: Run this script on a production system during peak hours without prior approval.
#   Don't: Interrupt the script while it is running.

# Prompt user to agree to the terms
echo ""
echo "IMPORTANT: This script is a powerful diagnostic tool. Please read the disclaimer above carefully."
echo ""
echo "Type 'AGREE' (case-sensitive) to continue, or anything else to exit:"
read agreement

if [ "$agreement" != "AGREE" ]; then
  echo "Agreement not provided. Exiting."
  exit 1
fi

# --- Initial Setup & OS Information ---

# Check for root/sudo privileges
if [[ $EUID -ne 0 ]]; then
  echo "This script requires root privileges. Please run with sudo." 
  exit 1
fi

# Determine the OS and version
os_info=$(cat /etc/os-release)
distro=$(grep '^NAME=' "$os_info" | cut -d'"' -f2)
version=$(grep '^VERSION=' "$os_info" | cut -d'"' -f2)

echo "Detected Distribution: $distro"
echo "Detected Version: $version"

# Create temporary directory to store scan results
tmp_dir=$(mktemp -d /tmp/security_scan.XXXXXXXXXX)
echo "Scan results will be stored in: $tmp_dir"

# --- Live System Analysis (Volatile Data Collection) ---

# Process & User Analysis
# List running processes
# Purpose: To identify any suspicious or unknown processes that might be running on the system.
# Functionality: The 'ps aux' command lists all running processes with detailed information including user, PID, CPU usage, memory usage, etc.
# Security Relevance: Malicious processes often try to hide or masquerade as legitimate processes. This check helps in identifying such anomalies.
echo "Listing running processes..."
ps aux > "$tmp_dir/processes.txt"

# List logged-in users
# Purpose: To identify who is currently logged into the system.
# Functionality: The 'who' command displays a list of currently logged-in users, their terminal, and login time.
# Security Relevance: Unauthorized users or unexpected login sessions can indicate a compromised system.
echo "Listing logged-in users..."
who > "$tmp_dir/logged_in_users.txt"

# List loaded kernel modules/extensions
# Purpose: To identify any suspicious or unknown kernel modules that might be loaded.
# Functionality: The 'lsmod' command lists all loaded kernel modules.  Kernel modules run with the highest privileges and can be used to hide malicious activity.
# Security Relevance: Rootkits often use kernel modules to hide their presence and gain control of the system.
echo "Listing loaded kernel modules..."
lsmod > "$tmp_dir/kernel_modules.txt"

# --- Network Triage ---

# Show active network connections
# Purpose: To identify any unauthorized or suspicious network connections.
# Functionality: The 'netstat -tulnp' command lists all active TCP and UDP connections with the process ID (PID) and program name.
# Security Relevance: Backdoors and malware often establish network connections to communicate with external servers.
echo "Listing active network connections..."
netstat -tulnp > "$tmp_dir/network_connections.txt"

# Alternatively use ss command
# Purpose: Another way to check active network connections.
# Functionality: The 'ss -tulnp' command lists TCP and UDP socket connections. `-t` is for TCP, `-u` is for UDP, `-l` is for listening sockets, `-n` shows numerical addresses, and `-p` shows the process using the socket.
# Security Relevance: Provides a different perspective on network activity, potentially revealing hidden connections.
echo "Listing active network connections with ss..."
ss -tulnp > "$tmp_dir/network_connections_ss.txt"

# Identify processes with open ports
# Purpose: To identify which processes are listening on which ports.
# Functionality: The 'lsof -i -n' command lists open files, including network sockets, and displays the associated process information.
# Security Relevance: Helps identify processes that are listening on unusual or unexpected ports, which could indicate a backdoor or malicious service.
echo "Listing processes with open ports..."
lsof -i -n > "$tmp_dir/open_ports.txt"

# --- Filesystem & Persistence Analysis ---

# Find recently modified files (last 24 hours)
# Purpose: To identify files that have been recently modified, which could indicate suspicious activity.
# Functionality: The 'find / -type f -mtime -1' command searches the entire filesystem for files modified within the last 24 hours. The '-type f' option limits the search to files, and '-mtime -1' specifies the modification time.
# Security Relevance: Attackers often modify files to install backdoors, hide their tracks, or steal data.
echo "Finding recently modified files (last 24 hours)..."
find / -type f -mtime -1 2>/dev/null > "$tmp_dir/recently_modified_files.txt"

# Find SUID/SGID files
# Purpose: To identify files that have the SUID or SGID bit set, which allows them to be executed with elevated privileges.
# Functionality: The 'find / -perm +4000 -o -perm +2000' command searches the entire filesystem for files with the SUID or SGID bit set. The '-perm +4000' option searches for SUID files, and '-perm +2000' searches for SGID files.  The `2>/dev/null` redirects errors to prevent displaying errors about permissions.
# Security Relevance: SUID/SGID files can be exploited by attackers to gain root privileges.
echo "Finding SUID/SGID files..."
find / -perm +4000 -o -perm +2000 2>/dev/null > "$tmp_dir/suid_sgid_files.txt"

# Find world-writable files
# Purpose: To identify files that are writable by any user, which can be a security risk.
# Functionality: The 'find / -perm -2 -type f' command searches for files that are world-writable. `-perm -2` finds files that have the world-writable bit set, and `-type f` limits the search to files.
# Security Relevance: World-writable files can be modified by attackers to inject malicious code or gain unauthorized access.
echo "Finding world-writable files..."
find / -perm -2 -type f 2>/dev/null > "$tmp_dir/world_writable_files.txt"

# Find suspicious hidden files (starting with .)
# Purpose: To identify hidden files and directories that might be used to conceal malicious activity.
# Functionality: The 'find / -name ".*" -type f' command searches for files starting with a dot. `2>/dev/null` redirects errors to prevent displaying errors about permissions.
# Security Relevance: Attackers often hide files and directories to avoid detection.
echo "Finding suspicious hidden files..."
find / -name ".*" -type f 2>/dev/null > "$tmp_dir/hidden_files.txt"

# Check persistence mechanisms: cron jobs
# Purpose: To identify scheduled tasks that might be used to execute malicious code.
# Functionality: The 'ls -l /etc/cron* /var/spool/cron/* /etc/anacrontab' command lists all cron jobs.  Cron jobs are scheduled tasks that run automatically at specified times or intervals.
# Security Relevance: Attackers can use cron jobs to schedule malicious code to run automatically on a regular basis.
echo "Checking cron jobs..."
ls -l /etc/cron* /var/spool/cron/* /etc/anacrontab 2>/dev/null > "$tmp_dir/cron_jobs.txt"

# Check persistence mechanisms: systemd services/timers
# Purpose: To identify systemd services and timers that might be used to execute malicious code.
# Functionality: The 'systemctl list-unit-files --type=service,timer' command lists all systemd service and timer unit files. Systemd is a system and service manager for Linux.
# Security Relevance: Attackers can use systemd services and timers to schedule malicious code to run automatically on a regular basis.
echo "Checking systemd services and timers..."
systemctl list-unit-files --type=service,timer 2>/dev/null > "$tmp_dir/systemd_services_timers.txt"

# Check authorized SSH keys for all users
# Purpose: To identify any unauthorized SSH keys that might be used to gain access to the system.
# Functionality: The script iterates through all user home directories and checks for authorized SSH keys in the '.ssh/authorized_keys' file.  SSH keys are used to authenticate users without requiring a password.
# Security Relevance: Attackers can add their own SSH keys to gain persistent access to the system.
echo "Checking authorized SSH keys..."
for user in $(cut -d: -f1 /etc/passwd); do
  if [ -d "/home/$user/.ssh" ]; then
    if [ -f "/home/$user/.ssh/authorized_keys" ]; then
      echo "User: $user"
      cat "/home/$user/.ssh/authorized_keys" >> "$tmp_dir/authorized_keys.txt"
    fi
  fi
done

# --- Log & Account Analysis ---

# Analyze authentication logs (last 24 hours)
# Purpose: To identify any suspicious login attempts or failed authentication attempts.
# Functionality: The 'grep "Failed password" /var/log/auth.log /var/log/secure /var/log/audit/audit.log*' command searches the authentication logs for failed password attempts. Authentication logs record user login and logout activity.
# Security Relevance: Repeated failed login attempts can indicate a brute-force attack.
echo "Analyzing authentication logs..."
grep "Failed password" /var/log/auth.log /var/log/secure /var/log/audit/audit.log* 2>/dev/null > "$tmp_dir/auth_logs.txt"

# Check user command histories
# Purpose: To identify any suspicious or unusual commands that have been executed by users.
# Functionality: The script iterates through all user home directories and checks for the '.bash_history' file. The .bash_history file contains a list of commands that have been executed by the user.
# Security Relevance: Attackers might use the command history to hide their tracks or to identify sensitive information.
echo "Checking user command histories..."
for user in $(cut -d: -f1 /etc/passwd); do
  if [ -f "/home/$user/.bash_history" ]; then
    echo "User: $user"
    cat "/home/$user/.bash_history" >> "$tmp_dir/command_history.txt"
  fi
done

# Audit user/group accounts for anomalies (e.g., UID 0 users)
# Purpose: To identify any unauthorized or suspicious user or group accounts.
# Functionality: The script checks for users with UID 0 (root) other than the root user.
# Security Relevance: Attackers might create unauthorized user accounts to gain access to the system.
echo "Auditing user accounts..."
awk -F: '($3 == 0) {print $1}' /etc/passwd > "$tmp_dir/uid_zero_users.txt"

# Find any accounts having root access beside root user
# Purpose: to check if there is any other user beside root having the root access
# Functionality: compare the users list with the root user
# Security Relevance: To ensure no one other than root user has the root access
echo "Check user having root access beside root user..."
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -v '^root$' > "$tmp_dir/non_root_uid_zero_users.txt"

# --- Rootkit Detection ---

# Recommend running tools like rkhunter and chkrootkit
# Purpose: To detect the presence of rootkits on the system.
# Functionality: Recommends the use of rkhunter and chkrootkit, which are specialized tools for detecting rootkits.
# Security Relevance: Rootkits are malicious software that hide their presence and activities from the operating system.
echo ""
echo "Rootkit detection: It is highly recommended to run rkhunter and chkrootkit for a more thorough rootkit scan."
echo "You can install them with: sudo apt-get install rkhunter chkrootkit or sudo yum install rkhunter chkrootkit"
echo "To run them: sudo rkhunter --check and sudo chkrootkit"
echo ""

# --- Backconnect backdoor checking ---
# Purpose: to check if there is a backdoor trying to make a reverse connection
# Functionality: use the netstat command to check the established connection and filter out based on estabilished connection with process id and then check the process id's working directory.
# Security Relevance: Backdoor attack through reverse connection by creating a malicious script.
echo "Checking for backconnect backdoor..."
#netstat -natp | grep ESTABLISHED > "$tmp_dir/backconnect.txt"

# --- HTML Report Generation ---

echo "Generating HTML report..."

cat <<EOF > "$tmp_dir/report.html"
<!DOCTYPE html>
<html>
<head>
<title>Security Scan Report</title>
<style>
body { font-family: Arial, sans-serif; }
h1 { color: #333; }
h2 { color: #555; }
pre { background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }
.section { margin-bottom: 20px; }
.header { background-color: #007BFF; color: white; padding: 10px; margin-bottom: 10px; }
.footer { background-color: #f0f0f0; padding: 5px; text-align: center; }
</style>
</head>
<body>
<div class="header">
<h1>Security Scan Report</h1>
</div>

<div class="section">
<h2>Detected Distribution</h2>
<pre>$distro $version</pre>
</div>

<div class="section">
<h2>Running Processes</h2>
<pre>
$(cat "$tmp_dir/processes.txt")
</pre>
</div>

<div class="section">
<h2>Logged-in Users</h2>
<pre>
$(cat "$tmp_dir/logged_in_users.txt")
</pre>
</div>

<div class="section">
<h2>Kernel Modules</h2>
<pre>
$(cat "$tmp_dir/kernel_modules.txt")
</pre>
</div>

<div class="section">
<h2>Network Connections</h2>
<pre>
$(cat "$tmp_dir/network_connections.txt")
</pre>
</div>

<div class="section">
<h2>Open Ports</h2>
<pre>
$(cat "$tmp_dir/open_ports.txt")
</pre>
</div>

<div class="section">
<h2>Recently Modified Files</h2>
<pre>
$(cat "$tmp_dir/recently_modified_files.txt")
</pre>
</div>

<div class="section">
<h2>SUID/SGID Files</h2>
<pre>
$(cat "$tmp_dir/suid_sgid_files.txt")
</pre>
</div>

<div class="section">
<h2>World Writable Files</h2>
<pre>
$(cat "$tmp_dir/world_writable_files.txt")
</pre>
</div>

<div class="section">
<h2>Hidden Files</h2>
<pre>
$(cat "$tmp_dir/hidden_files.txt")
</pre>
</div>

<div class="section">
<h2>Cron Jobs</h2>
<pre>
$(cat "$tmp_dir/cron_jobs.txt")
</pre>
</div>

<div class="section">
<h2>Systemd Services and Timers</h2>
<pre>
$(cat "$tmp_dir/systemd_services_timers.txt")
</pre>
</div>

<div class="section">
<h2>Authorized SSH Keys</h2>
<pre>
$(cat "$tmp_dir/authorized_keys.txt")
</pre>
</div>

<div class="section">
<h2>Authentication Logs</h2>
<pre>
$(cat "$tmp_dir/auth_logs.txt")
</pre>
</div>

<div class="section">
<h2>Command History</h2>
<pre>
$(cat "$tmp_dir/command_history.txt")
</pre>
</div>

<div class="section">
<h2>UID 0 Users</h2>
<pre>
$(cat "$tmp_dir/uid_zero_users.txt")
</pre>
</div>

<div class="section">
<h2>Non Root UID 0 Users</h2>
<pre>
$(cat "$tmp_dir/non_root_uid_zero_users.txt")
</pre>
</div>


<div class="footer">
<p>Security Scan Report Generated.</p>
</div>
</body>
</html>
EOF

echo "HTML report generated: $tmp_dir/report.html"


echo "Scan completed. Results are stored in $tmp_dir"
