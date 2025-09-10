<#
.SYNOPSIS
    Performs a security audit and investigation for backdoors, rootkits, and indicators of compromise on a Windows system.

.DESCRIPTION
    This script is a powerful diagnostic tool designed for security analysis. It performs
    extensive read-only checks on system configuration, logs, and processes. It does
    NOT modify system files or settings. However, running diagnostic tools can consume
    system resources. Use this script at your own risk. The creators are not responsible
    for any direct or indirect damages.

    Do's and Don'ts:
    * Do: Run this script in a controlled environment.
    * Do: Review the script's code before executing it.
    * Don't: Run this script on a production system during peak hours without prior approval.
    * Don't: Interrupt the script while it is running.

.NOTES
    Refixed and recoded by moni
#>

#region User Agreement

# Display the disclaimer message to the user
Write-Host "This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages." -ForegroundColor Yellow
Write-Host "" # Add an empty line for better readability.

# Prompt the user to type 'AGREE' to continue
$agreement = Read-Host "Type 'AGREE' to continue" # Prompt the user for input.

# Check if the user entered 'AGREE'
if ($agreement -ne "AGREE") {
    Write-Host "Agreement not provided. Exiting." -ForegroundColor Red # Notify user the agreement was not provided.
    exit # Exit the script
}

#endregion

#region Initial Setup & OS Information

# Check for Administrator privileges
# Purpose: Ensure the script has the necessary permissions to perform its tasks.
# Functionality: Checks if the current user has administrator privileges.
# Security Relevance: Many security-related checks require elevated privileges.
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as administrator." -ForegroundColor Red
    exit # Exit if not running as administrator
}

# Get and display detailed OS and version information
# Purpose: Provide information about the system being analyzed.
# Functionality: Uses Get-ComputerInfo to retrieve OS-related information.
# Security Relevance: Knowing the OS version is crucial for identifying relevant vulnerabilities.
Write-Host "Gathering OS Information..." -ForegroundColor Cyan
$OSInfo = Get-ComputerInfo
Write-Host "OS Name: $($OSInfo.OsName)"
Write-Host "OS Version: $($OSInfo.OsVersion)"
Write-Host "Windows Build Number: $($OSInfo.OsBuildNumber)"
Write-Host "Windows Install Date: $($OSInfo.OsInstallDate)"

# Create a temporary file to store the results
$tmpFile = Join-Path $env:TEMP "security_scan_results_$((Get-Date -Format 'yyyyMMddHHmmss')).txt"
Write-Host "Results will be saved to: $tmpFile" -ForegroundColor Green

function Write-Result {
    param (
        [string]$Message
    )
    Write-Host $Message
    Add-Content -Path $tmpFile -Value $Message
}

#endregion

#region Live System Analysis

# Process & User Analysis
# Purpose: Identify suspicious processes or unauthorized users.
# Functionality: Uses Get-Process to list running processes and their details.
# Security Relevance: Backdoors or malware often run as hidden or disguised processes.
Write-Result "`n[+] Running Processes:"
Get-Process | ForEach-Object {
    Write-Result "  Process Name: $($_.ProcessName), ID: $($_.Id), CPU: $($_.CPU), Memory (KB): $($_.WorkingSet / 1024)"
}

# Get process command-line arguments using WMI
# Purpose: Identify suspicious command-line arguments used by running processes
# Functionality: Uses Get-WmiObject to retrieve process information including command line
# Security Relevance: Suspicious command lines can indicate malicious activity
Write-Result "`n[+] Process Command Lines:"
Get-WmiObject -Class Win32_Process | ForEach-Object {
    Write-Result "  Process Name: $($_.Name), ID: $($_.ProcessId), Command Line: $($_.CommandLine)"
}

# Active user sessions
# Purpose: Identify who is currently logged in.
# Functionality: Uses query user to list active user sessions.
# Security Relevance: Unauthorized user sessions are a sign of compromise.
Write-Result "`n[+] Active User Sessions:"
query user | ForEach-Object {
    Write-Result "  $_"
}

# Network Triage
# Purpose: Identify suspicious network connections.
# Functionality: Uses Get-NetTCPConnection and Get-NetUDPEndpoint to list active connections.
# Security Relevance: Backdoors often establish network connections to external servers.
Write-Result "`n[+] Active TCP Connections:"
Get-NetTCPConnection | ForEach-Object {
    Write-Result "  Local Address: $($_.LocalAddress):$($_.LocalPort), Remote Address: $($_.RemoteAddress):$($_.RemotePort), State: $($_.State), Owning Process: $($_.OwningProcess)"
}

Write-Result "`n[+] Active UDP Endpoints:"
Get-NetUDPEndpoint | ForEach-Object {
    Write-Result "  Local Address: $($_.LocalAddress):$($_.LocalPort), Owning Process: $($_.OwningProcess)"
}

#endregion

#region Vulnerability & Patch Analysis

# List installed hotfixes/KBs
# Purpose: Identify missing security patches.
# Functionality: Uses Get-HotFix to list installed hotfixes.
# Security Relevance: Unpatched systems are vulnerable to known exploits.
Write-Result "`n[+] Installed Hotfixes (KBs):"
Get-HotFix | ForEach-Object {
    Write-Result "  HotfixID: $($_.HotfixID), InstalledOn: $($_.InstalledOn), Description: $($_.Description)"
}

#endregion

#region Filesystem & Persistence Analysis

# Find recently modified files in key system directories
# Purpose: Identify files that might have been recently modified by an attacker.
# Functionality: Uses Get-ChildItem to find files modified in the last 7 days.
# Security Relevance: Attackers often modify system files to install backdoors or hide their presence.
Write-Result "`n[+] Recently Modified Files (Last 7 Days):"
$SystemDirectories = @(
    "$env:SystemRoot",
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:AppData",
    "$env:LocalAppData"
)

foreach ($dir in $SystemDirectories) {
    try {
        Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | ForEach-Object {
            Write-Result "  Path: $($_.FullName), Last Write Time: $($_.LastWriteTime)"
        }
    } catch {
        Write-Warning "Error accessing directory: $dir - $($_.Exception.Message)"
    }
}

# Check persistence mechanisms
# Scheduled Tasks
# Purpose: Detect tasks created by attackers to maintain persistence.
# Functionality: Uses Get-ScheduledTask to list scheduled tasks.
# Security Relevance: Malicious scheduled tasks can execute code at regular intervals.
Write-Result "`n[+] Scheduled Tasks:"
Get-ScheduledTask | Where-Object {$_.TaskName -notlike "*Windows*"} | ForEach-Object {
 Write-Result "  Task Name: $($_.TaskName), State: $($_.State), Last Run Time: $($_.LastRunTime), Path: $($_.TaskPath)"
}

# Services
# Purpose: Detect suspicious services.
# Functionality: Uses Get-Service to list services.
# Security Relevance: Malware can install itself as a service to run automatically.
Write-Result "`n[+] Services:"
Get-Service | Where-Object {$_.Name -notlike "*Microsoft*"} | ForEach-Object {
    Write-Result "  Service Name: $($_.Name), Status: $($_.Status), Start Type: $($_.StartType), Display Name: $($_.DisplayName)"
}

# Registry Run keys
# Purpose: Detect programs that start automatically when the user logs in.
# Functionality: Uses Get-ItemProperty to read registry keys.
# Security Relevance: Malware often uses Run keys to achieve persistence.
Write-Result "`n[+] Registry Run Keys:"
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $RunKeys) {
    try {
        Get-ItemProperty -Path $key | ForEach-Object {
            foreach ($property in $_.PSObject.Properties) {
                if ($property.Name -ne "PSPath" -and $property.Name -ne "PSParentPath" -and $property.Name -ne "PSChildName" -and $property.Name -ne "PSDrive" -and $property.Name -ne "PSProvider") {
                    Write-Result "  Key: $key, Name: $($property.Name), Value: $($property.Value)"
                }
            }
        }
    } catch {
        Write-Warning "Error accessing registry key: $key - $($_.Exception.Message)"
    }
}

#endregion

#region Log & Account Analysis

# Query the Windows Event Log
# Security Log (Failed Logons)
# Purpose: Identify failed logon attempts that might indicate brute-force attacks.
# Functionality: Uses Get-WinEvent to query the Security event log.
# Security Relevance: Excessive failed logon attempts can indicate a password guessing attack.
Write-Result "`n[+] Failed Logon Attempts (Security Log):"
Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object {$_.ID -eq 4625} | ForEach-Object {
    Write-Result "  TimeCreated: $($_.TimeCreated), User: $($_.Properties[5].Value), Source IP: $($_.Properties[19].Value)"
}

# System Log (Service Creation)
# Purpose: Detect newly created services that might be malicious.
# Functionality: Uses Get-WinEvent to query the System event log.
# Security Relevance: Malware often installs itself as a service.
Write-Result "`n[+] Newly Created Services (System Log):"
Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.ID -eq 7045} | ForEach-Object {
    Write-Result "  TimeCreated: $($_.TimeCreated), Service Name: $($_.Properties[0].Value), Image Path: $($_.Properties[1].Value)"
}

# Audit local user accounts and group memberships
# Purpose: Identify unauthorized user accounts or group memberships.
# Functionality: Uses Get-LocalUser and Get-LocalGroupMember to list users and group members.
# Security Relevance: Attackers might create new accounts or add existing accounts to privileged groups.
Write-Result "`n[+] Local User Accounts:"
Get-LocalUser | ForEach-Object {
    Write-Result "  Name: $($_.Name), Enabled: $($_.Enabled), LastLogon: $($_.LastLogon)"
}

Write-Result "`n[+] Local Group Memberships (Administrators):"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    Write-Result "  Member: $($_.Name)"
}

# Check for accounts with RID 500 (Administrator)
Write-Result "`n[+] Checking for accounts with RID 500 (Administrator):"
$adminAccount = Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.SID -like 'S-1-5-21-*-500'}
if ($adminAccount) {
 Write-Result "  Account with RID 500 found: $($adminAccount.Name)"
} else {
 Write-Result "  No account with RID 500 found."
}

#endregion

#region HTML Report Generation

# Generate HTML report
# Purpose: Create a formatted HTML report of the scan results.
# Functionality: Reads the content of the temporary file and generates an HTML file with a custom theme.
# Security Relevance: Provides an easily readable and shareable summary of the security scan.

Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan

$htmlFile = Join-Path $env:TEMP "security_scan_report_$((Get-Date -Format 'yyyyMMddHHmmss')).html"

# Read the content from the temporary file
$results = Get-Content -Path $tmpFile

# Define the HTML content with a theme
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
<title>Security Scan Report</title>
<style>
body {
 font-family: Arial, sans-serif;
 background-color: #f4f4f4;
 color: #333;
 margin: 20px;
}

h1 {
 color: #4CAF50;
}

.section {
 background-color: #fff;
 padding: 10px;
 margin-bottom: 20px;
 border: 1px solid #ddd;
 border-radius: 5px;
}

.section-title {
 color: #4CAF50;
 font-size: 1.2em;
 margin-bottom: 10px;
}

.log-entry {
 margin-bottom: 5px;
 word-wrap: break-word;
}

.log-entry:nth-child(even) {
 background-color: #f9f9f9;
}

/* Add more theme-related styles here */
</style>
</head>
<body>
 <h1>Security Scan Report</h1>

 <div class="section">
 <div class="section-title">OS Information</div>
 <div class="log-entry">OS Name: $($OSInfo.OsName)</div>
 <div class="log-entry">OS Version: $($OSInfo.OsVersion)</div>
 <div class="log-entry">Windows Build Number: $($OSInfo.OsBuildNumber)</div>
 <div class="log-entry">Windows Install Date: $($OSInfo.OsInstallDate)</div>
 </div>

 <div class="section">
 <div class="section-title">Scan Results</div>
 <pre style="white-space: pre-wrap;">$($results -join "`n")</pre>
 </div>

</body>
</html>
"@

# Write the HTML content to the file
$htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8

Write-Host "HTML report generated at: $htmlFile" -ForegroundColor Green

#endregion

Write-Host "Script completed. Results saved to $tmpFile and $htmlFile" -ForegroundColor Green
