# sys-check: Linux & Windows Security Auditing Tool

`sys-check` is a comprehensive security auditing script for both Linux and Windows systems. It is designed to be run on a live system to perform a wide range of checks, collecting volatile and non-volatile data to identify potential security weaknesses, misconfigurations, and indicators of compromise.

The script is heavily commented and designed for security analysts, system administrators, and forensics professionals. It generates a detailed report in both plain text and HTML format (for Linux) for easy analysis.

## Core Features

-   **Cross-Platform**: Generates scripts for both Linux-based systems and Windows.
-   **User Agreement**: Includes a mandatory user agreement prompt to ensure responsible use.
-   **Volatile Data Collection**: Captures live system data, including running processes, logged-in users, and network connections.
-   **Filesystem Analysis**: Scans for insecure file permissions, recently modified files, and other anomalies.
-   **Persistence-Mechanism Checks**: Audits common persistence locations, such as cron jobs (Linux), scheduled tasks (Windows), and registry keys (Windows).
-   **Log & Account Auditing**: Analyzes authentication logs for suspicious activity and audits user accounts.
-   **HTML Report Generation**: Automatically creates a formatted HTML report for Linux scan results.

## Getting Started

### Prerequisites

-   A Linux or Windows operating system.
-   Root or `sudo` privileges for Linux, and Administrator privileges for Windows are required to run the script effectively.

### How to Run

1.  **Generate and download the script** from the application.
2.  **For Linux**:
    -   Make the script executable:
        ```bash
        chmod +x your_script_name.sh
        ```
    -   Run with root privileges:
        ```bash
        sudo ./your_script_name.sh
        ```
3.  **For Windows**:
    -   Open PowerShell as an Administrator.
    -   You may need to set the execution policy to run the script:
        ```powershell
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
        ```
    -   Run the script:
        ```powershell
        .\your_script_name.ps1
        ```

4.  **Agree to the Terms**:
    The script will display a disclaimer. You must type `AGREE` to proceed with the scan. If you do not agree, the script will exit.

5.  **Review the Output**:
    -   On **Linux**, the script will print its findings to the console and create a `security_report.html` file.
    -   On **Windows**, the script will output its findings directly to the PowerShell console.

## Security Checks Performed

### For Linux Systems:

#### 1. Live System Analysis
-   **Running Processes**: Lists all running processes (`ps aux`).
-   **Logged-in Users**: Shows currently active user sessions (`who`).
-   **Loaded Kernel Modules**: Lists all loaded modules (`lsmod`).
-   **Network Connections**: Displays active network connections (`netstat`, `ss`).
-   **Processes with Open Ports**: Identifies which processes are listening on the network (`lsof -i`).

#### 2. Filesystem & Persistence
-   **Recently Modified Files**: Finds files modified within the last 24 hours.
-   **SUID/SGID Files**: Locates files with special permissions that could be exploited.
-   **World-Writable Files**: Identifies files that can be modified by any user.
-   **Suspicious Hidden Files**: Searches for hidden "dotfiles" used by attackers.
-   **Cron Jobs**: Checks all cron directories and user crontabs.
-   **Systemd Services**: Lists systemd services and timers.
-   **SSH Keys**: Examines `authorized_keys` files for unauthorized keys.

#### 3. Log & Account Auditing
-   **Authentication Logs**: Scans logs for failed password attempts and invalid usernames.
-   **User Command Histories**: Dumps user command history files.
-   **Anomalous User Accounts**: Checks for accounts with a User ID (UID) of 0.

#### 4. Rootkit Detection
-   Recommends installing and running `rkhunter` and `chkrootkit`.

### For Windows Systems:

#### 1. Live System Analysis
-   **Process & User Analysis**: Lists running processes (`Get-Process`) and active user sessions (`query user`).
-   **Network Triage**: Shows active TCP/UDP connections and the processes that own them (`Get-NetTCPConnection`).

#### 2. Vulnerability & Patch Analysis
-   **Installed Hotfixes**: Lists installed Windows updates (`Get-HotFix`) to identify missing security patches.

#### 3. Filesystem & Persistence Analysis
-   **Recently Modified Files**: Finds recently modified files in key system directories.
-   **Persistence Mechanisms**:
    -   **Scheduled Tasks**: Checks for potentially malicious scheduled tasks (`Get-ScheduledTask`).
    -   **Services**: Audits system services for unusual entries (`Get-Service`).
    -   **Registry Run Keys**: Examines registry keys used for startup persistence (`Get-ItemProperty`).

#### 4. Log & Account Analysis
-   **Windows Event Log**: Queries the Security and System logs for suspicious events like failed logons or service creation (`Get-WinEvent`).
-   **Local User Accounts**: Audits local users and group memberships (`Get-LocalUser`, `Get-LocalGroupMember`).

## Disclaimer

This script is a powerful diagnostic tool and should be used responsibly.
It performs read-only checks and does not modify system files.
However, running diagnostic tools can consume system resources. 
Use this script at your own risk. The creators are not responsible for any damages. 
Always review the code before executing it on a critical system.
