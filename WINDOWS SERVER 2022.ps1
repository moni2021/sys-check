<#
Refixed and recoded by moni

Disclaimer:
This script is a powerful diagnostic tool designed for security analysis. It performs extensive read-only checks on system configuration, logs, and processes. It does NOT modify system files or settings. However, running diagnostic tools can consume system resources. Use this script at your own risk. The creators are not responsible for any direct or indirect damages.

Do's and Don'ts:
* Do: Run this script in a controlled environment.
* Do: Review the script's code before executing it.
* Don't: Run this script on a production system during peak hours without prior approval.
* Don't: Interrupt the script while it is running.
#>

# Prompt the user to agree to the terms
Write-Host "Disclaimer: This script is a powerful diagnostic tool designed for security analysis... (see full disclaimer above)." -ForegroundColor Yellow
$agreement = Read-Host "Type 'AGREE' to continue"

if ($agreement -ne "AGREE") {
 Write-Host "Agreement not provided. Exiting." -ForegroundColor Red
 Exit
}

#region Initial Setup & OS Information

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
 Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
 Exit
}

# Get and display detailed OS and version information
Write-Host "Gathering OS information..." -ForegroundColor Green
$OSInfo = Get-ComputerInfo
Write-Host "OS Name: $($OSInfo.OsName)"
Write-Host "OS Version: $($OSInfo.OsVersion)"
Write-Host "Windows Build Number: $($OSInfo.OsBuildNumber)"
Write-Host "Windows Edition: $($OSInfo.OsEditionId)"

# Define the temporary file path to store the output
$tempFilePath = Join-Path $env:TEMP "security_scan_results.txt"

# Define the HTML output file path
$htmlFilePath = Join-Path $env:TEMP "security_scan_report.html"

# Function to write output to both console and the temp file
function Write-Log {
 param (
 [string]$Message
 )
 Write-Host $Message
 Add-Content -Path $tempFilePath -Value $Message
}

Write-Log "Script started at: $(Get-Date)"

#endregion

#region Live System Analysis

# Process & User Analysis
Write-Log "\n--- Processes & Users ---"

# List running processes and their command-line arguments
Write-Log "\nRunning Processes:"
Get-Process | ForEach-Object {
 $processName = $_.ProcessName
 try {
 # Get the command line using WMI. This can fail if not run as administrator or if the process is protected.
 $CommandLine = (Get-WmiObject win32_process -Filter "ProcessID=$($_.Id)").CommandLine
 } catch {
 $CommandLine = "Unable to retrieve command line (Access Denied or Process Protected)"
 }
 Write-Log " Process Name: $($processName)"
 Write-Log " PID: $($_.Id)"
 Write-Log " Command Line: $($CommandLine)"
 Write-Log "---"
}

# Active user sessions
Write-Log "\nActive User Sessions:"
query user | Out-String | Write-Log

# Network Triage
Write-Log "\n--- Network Connections ---"

# Show active TCP connections
Write-Log "\nActive TCP Connections:"
Get-NetTCPConnection | ForEach-Object {
 $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
 $processName = if ($process) {$process.ProcessName} else {"N/A"}
 Write-Log " Local Address: $($_.LocalAddress):$($_.LocalPort)"
 Write-Log " Remote Address: $($_.RemoteAddress):$($_.RemotePort)"
 Write-Log " State: $($_.State)"
 Write-Log " Process Name: $($processName)"
 Write-Log "---"
}

# Show active UDP endpoints
Write-Log "\nActive UDP Endpoints:"
Get-NetUDPEndpoint | ForEach-Object {
 $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
 $processName = if ($process) {$process.ProcessName} else {"N/A"}
 Write-Log " Local Address: $($_.LocalAddress):$($_.LocalPort)"
 Write-Log " Process Name: $($processName)"
 Write-Log "---"
}

#endregion

#region Vulnerability & Patch Analysis

Write-Log "\n--- Vulnerability & Patch Analysis ---"

# List installed hotfixes/KBs
Write-Log "\nInstalled Hotfixes/KBs:"
Get-HotFix | Sort-Object InstalledOn -Descending | ForEach-Object {
 Write-Log " HotfixID: $($_.HotfixID)"
 Write-Log " Description: $($_.Description)"
 Write-Log " Installed On: $($_.InstalledOn)"
 Write-Log "---"
}

#endregion

#region Filesystem & Persistence Analysis

Write-Log "\n--- Filesystem & Persistence Analysis ---"

# Find recently modified files in key system directories (last 7 days)
Write-Log "\nRecently Modified Files (last 7 days) in System Directories:"
$SystemPaths = @(
 "$env:windir\System32",
 "$env:windir",
 "$env:ProgramFiles",
 "$env:ProgramFiles(x86)",
 "C:\",
 "$env:AppData",
 "$env:LocalAppData"
)

foreach ($path in $SystemPaths) {
 Write-Log "\nScanning Path: $path"
 Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | ForEach-Object {
 Write-Log " File: $($_.FullName)"
 Write-Log " Last Modified: $($_.LastWriteTime)"
 Write-Log "---"
 }
}

# Check persistence mechanisms
Write-Log "\nPersistence Mechanisms:"

# Scheduled Tasks
Write-Log "\nScheduled Tasks:"
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\Windows\*"} | ForEach-Object {
 Write-Log " Task Name: $($_.TaskName)"
 Write-Log " Task Path: $($_.TaskPath)"
 Write-Log " State: $($_.State)"
 Write-Log "---"
}

# Services
Write-Log "\nServices:"
Get-Service | Where-Object {$_.StartType -ne "Disabled"} | ForEach-Object {
 Write-Log " Service Name: $($_.ServiceName)"
 Write-Log " Display Name: $($_.DisplayName)"
 Write-Log " Status: $($_.Status)"
 Write-Log " Start Type: $($_.StartType)"
 Write-Log "---"
}

# Registry Run keys
Write-Log "\nRegistry Run Keys:"
$RunKeys = @(
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $RunKeys) {
 Write-Log "\nScanning Registry Key: $key"
 Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
 $_.PSObject.Properties | Where-Object {$_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")} | ForEach-Object {
 Write-Log " Name: $($_.Name)"
 Write-Log " Value: $($_.Value)"
 Write-Log "---"
 }
 }
}

#endregion

#region Log & Account Analysis

Write-Log "\n--- Log & Account Analysis ---"

# Query the Windows Event Log (Security, System) for suspicious events
Write-Log "\nWindows Event Log (Security - Failed Logons - last 24H):"
Get-WinEvent -LogName Security -FilterXPath "//*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" | ForEach-Object {
 Write-Log " Event ID: $($_.Id)"
 Write-Log " Time Created: $($_.TimeCreated)"
 Write-Log " Message: $($_.Message)"
 Write-Log "---"
}

Write-Log "\nWindows Event Log (System - Service Creation - last 24H):"
Get-WinEvent -LogName System -FilterXPath "//*[System[EventID=7045 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" | ForEach-Object {
 Write-Log " Event ID: $($_.Id)"
 Write-Log " Time Created: $($_.TimeCreated)"
 Write-Log " Message: $($_.Message)"
 Write-Log "---"
}

# Audit local user accounts and group memberships
Write-Log "\nLocal User Accounts:"
Get-LocalUser | ForEach-Object {
 Write-Log " Name: $($_.Name)"
 Write-Log " Enabled: $($_.Enabled)"
 Write-Log " AccountExpires: $($_.AccountExpires)"
 Write-Log "---"
}

Write-Log "\nLocal Group Memberships (Administrators):"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
 Write-Log " Name: $($_.Name)"
 Write-Log " ObjectClass: $($_.ObjectClass)"
 Write-Log "---"
}

#endregion


#region Generate HTML Report

Write-Log "\n--- Generating HTML Report ---"

# Read the content of the temporary file
$content = Get-Content -Path $tempFilePath

# Generate HTML content with a robust theme
$htmlHead = @"
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>Security Scan Report</title>
 <style>
 body {
 font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
 margin: 20px;
 background-color: #f4f4f4;
 color: #333;
 }

 h1 {
 color: #0056b3;
 border-bottom: 2px solid #0056b3;
 padding-bottom: 5px;
 }

 h2 {
 color: #0056b3;
 margin-top: 20px;
 }

 pre {
 background-color: #e9e9e9;
 padding: 10px;
 border-radius: 5px;
 overflow-x: auto;
 }

 .log-entry {
 margin-bottom: 15px;
 border: 1px solid #ddd;
 padding: 10px;
 background-color: #fff;
 border-radius: 5px;
 }

 .log-header {
 font-weight: bold;
 color: #555;
 margin-bottom: 5px;
 }
 </style>
</head>
<body>
 <h1>Security Scan Report</h1>
"@

$htmlBody = ""

foreach ($line in $content) {
 $htmlBody += "<div class='log-entry'><pre>`$($line)`</pre></div>`n"
}

$htmlTail = @"
</body>
</html>
"@

$htmlContent = $htmlHead + $htmlBody + $htmlTail

# Write the HTML content to the file
$htmlContent | Out-File -FilePath $htmlFilePath -Encoding UTF8

Write-Log "HTML report generated at: $htmlFilePath"

#endregion

Write-Log "Script ended at: $(Get-Date)"
Write-Log "Scan results are saved to: $tempFilePath"

