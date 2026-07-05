<#
.SYNOPSIS
    Security Hardening State Enumeration Script

.DESCRIPTION
    Prints a readable snapshot of the system's security configuration.
    Run before and after Invoke-ServerHardening.ps1 to confirm changes.

.NOTES
    Project:    SYS-255 Final Project
    Authors:    Aaron Ho, Andrew Zombek, Nad AlDulaimi

.EXAMPLE
    .\Get-HardeningState.ps1
#>

#Requires -RunAsAdministrator

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$separator = "=" * 60
$section   = "-" * 60

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host $section -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host $section -ForegroundColor Cyan
}

function Write-Result {
    param([string]$Label, [string]$Value, [string]$Color = "White")
    Write-Host ("  {0,-36} {1}" -f $Label, $Value) -ForegroundColor $Color
}

Write-Host ""
Write-Host $separator -ForegroundColor Yellow
Write-Host " HARDENING STATE SNAPSHOT" -ForegroundColor Yellow
Write-Host " $timestamp" -ForegroundColor Yellow
Write-Host " Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host $separator -ForegroundColor Yellow


# ============================================================================
# MODULE 1: User Accounts
# ============================================================================

Write-Section "MODULE 1: User Accounts"

$accountsToCheck = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "Andrew", "Aaron")

foreach ($name in $accountsToCheck) {
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $user) {
        Write-Result "$name" "Not found" "DarkGray"
    } else {
        $status = if ($user.Enabled) { "ENABLED" } else { "Disabled" }
        $color  = if ($user.Enabled) { "Green" } else { "Gray" }
        Write-Result "$name" $status $color
    }
}

# Administrators group membership
Write-Host ""
Write-Host "  Administrators group members:" -ForegroundColor White
$adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
if ($adminMembers) {
    foreach ($m in $adminMembers) {
        $localUser = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $m.SID }
        $display   = if ($localUser) { $localUser.Name } else { $m.Name -replace "^.+\\", "" }
        Write-Host ("    - {0}" -f $display) -ForegroundColor White
    }
} else {
    Write-Host "    (none)" -ForegroundColor DarkGray
}


# ============================================================================
# MODULE 2: Password and Lockout Policy
# ============================================================================

Write-Section "MODULE 2: Password and Lockout Policy"

$netAccounts = net accounts 2>&1
$settings = @{}
foreach ($line in $netAccounts) {
    if ($line -match "^(.+?):\s+(.+)$") {
        $settings[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$minLen    = if ($settings["Minimum password length"])               { $settings["Minimum password length"] }               else { "N/A" }
$maxAge    = if ($settings["Maximum password age (days)"])          { $settings["Maximum password age (days)"] }          else { "N/A" }
$minAge    = if ($settings["Minimum password age (days)"])          { $settings["Minimum password age (days)"] }          else { "N/A" }
$history   = if ($settings["Length of password history maintained"]) { $settings["Length of password history maintained"] } else { "N/A" }
$threshold = if ($settings["Lockout threshold"])                    { $settings["Lockout threshold"] }                    else { "N/A" }
$duration  = if ($settings["Lockout duration (minutes)"])           { $settings["Lockout duration (minutes)"] }           else { "N/A" }
$window    = if ($settings["Lockout observation window (minutes)"]) { $settings["Lockout observation window (minutes)"] } else { "N/A" }

Write-Result "Min password length"       $minLen
Write-Result "Max password age (days)"   $maxAge
Write-Result "Min password age (days)"   $minAge
Write-Result "Password history"          $history
Write-Result "Lockout threshold"         $threshold
Write-Result "Lockout duration (min)"    $duration
Write-Result "Lockout window (min)"      $window


# ============================================================================
# MODULE 4: Audit Policy (spot check)
# ============================================================================

Write-Section "MODULE 4: Audit Policy (Spot Check)"

$auditCategories = @("Logon", "Logoff", "Account Lockout", "Credential Validation", "Process Creation")

foreach ($cat in $auditCategories) {
    $result = & auditpol.exe /get /subcategory:"$cat" 2>$null |
        Where-Object { $_ -match $cat }
    if ($result) {
        $value = ($result -replace "^\s+$cat\s+", "").Trim()
        Write-Result $cat $value
    } else {
        Write-Result $cat "Could not read" "DarkGray"
    }
}

$cmdLineReg = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
$cmdLineVal = if ($null -ne $cmdLineReg -and $cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) { "Enabled" } else { "Disabled" }
Write-Result "Command-line logging (4688)" $cmdLineVal


# ============================================================================
# MODULE 6: Firewall
# ============================================================================

Write-Section "MODULE 6: Windows Firewall"

$profiles = Get-NetFirewallProfile -All -ErrorAction SilentlyContinue
if ($profiles) {
    foreach ($p in $profiles) {
        $enabledStr  = if ($p.Enabled) { "ON" } else { "OFF" }
        $inboundStr  = $p.DefaultInboundAction.ToString()
        $outboundStr = $p.DefaultOutboundAction.ToString()
        Write-Result "$($p.Name) profile" "Enabled=$enabledStr  Inbound=$inboundStr  Outbound=$outboundStr"
    }
} else {
    # netsh fallback
    $netshOut = netsh advfirewall show allprofiles state 2>$null
    Write-Host "  (PowerShell cmdlet unavailable, using netsh)" -ForegroundColor DarkGray
    $netshOut | Where-Object { $_ -match "State" } | ForEach-Object {
        Write-Host "  $_" -ForegroundColor White
    }
}

$rulesToCheck = @(
    "Hardening - Block Inbound SMB (TCP 445)"
    "Hardening - Block Inbound RDP (TCP 3389)"
    "Hardening - Block Inbound NetBIOS (UDP 137)"
    "Hardening - Block Inbound NetBIOS (UDP 138)"
    "Hardening - Block Inbound NetBIOS (TCP 139)"
)

Write-Host ""
Write-Host "  Hardening firewall rules:" -ForegroundColor White
foreach ($rule in $rulesToCheck) {
    # Use netsh to check rule existence - Get-NetFirewallRule fails after
    # Administrator rename due to SID resolution errors
    $netshCheck = netsh advfirewall firewall show rule name="$rule" 2>$null
    $exists     = $netshCheck -match [regex]::Escape($rule)
    $status     = if ($exists) { "EXISTS" } else { "Not present" }
    $color      = if ($exists) { "Green" } else { "Gray" }
    Write-Result "  $rule" $status $color
}


# ============================================================================
# MODULE 7: Services
# ============================================================================

Write-Section "MODULE 7: Services"

$servicesToCheck = @(
    @{ Name = "RemoteRegistry";  Label = "Remote Registry" }
    @{ Name = "Spooler";         Label = "Print Spooler" }
    @{ Name = "TlntSvr";         Label = "Telnet" }
    @{ Name = "SNMP";            Label = "SNMP" }
    @{ Name = "XblAuthManager";  Label = "Xbox Live Auth Manager" }
    @{ Name = "WinRM";           Label = "Windows Remote Management" }
    @{ Name = "DiagTrack";       Label = "Connected User Exp & Telemetry" }
)

foreach ($svc in $servicesToCheck) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($null -eq $s) {
        Write-Result $svc.Label "Not installed" "DarkGray"
    } else {
        $wmi       = Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
        $startMode = if ($wmi) { $wmi.StartMode } else { "Unknown" }
        $status    = "$($s.Status) / $startMode"
        Write-Result $svc.Label $status
    }
}


# ============================================================================
# MODULE 8: Attack Surface
# ============================================================================

Write-Section "MODULE 8: Attack Surface Reduction"

# SMBv1
$smb1Reg = Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "SMB1" -ErrorAction SilentlyContinue
$smb1Val = if ($null -ne $smb1Reg -and $smb1Reg.SMB1 -eq 0) { "Disabled (registry)" } else { "Enabled or not set" }
Write-Result "SMBv1" $smb1Val

# LLMNR
$llmnrReg = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue
$llmnrVal = if ($null -ne $llmnrReg -and $llmnrReg.EnableMulticast -eq 0) { "Disabled" } else { "Enabled or not set" }
Write-Result "LLMNR" $llmnrVal

# Windows Script Host
$wshReg = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
    -Name "Enabled" -ErrorAction SilentlyContinue
$wshVal = if ($null -ne $wshReg -and $wshReg.Enabled -eq 0) { "Disabled" } else { "Enabled or not set" }
Write-Result "Windows Script Host" $wshVal

# Windows Defender
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Result "Defender Real-Time Protection" $(if ($defender.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" })
    Write-Result "Defender Behavior Monitoring"  $(if ($defender.BehaviorMonitorEnabled)    { "Enabled" } else { "Disabled" })
} else {
    Write-Result "Windows Defender" "Not available" "DarkGray"
}


# ============================================================================
# MODULE 9: Registry Hardening
# ============================================================================

Write-Section "MODULE 9: Registry Hardening"

$regChecks = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                                         Name = "RunAsPPL";                    Label = "LSASS RunAsPPL";              Expected = 1 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";                   Name = "UseLogonCredential";          Label = "WDigest Caching";             Expected = 0 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                                         Name = "NoLMHash";                    Label = "LM Hash Storage Disabled";    Expected = 1 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                                         Name = "LmCompatibilityLevel";        Label = "LM Compat Level (5=NTLMv2)";  Expected = 5 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                                         Name = "RestrictAnonymousSAM";        Label = "Restrict Anon SAM Enum";      Expected = 1 }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";                  Name = "NoDriveTypeAutoRun";          Label = "AutoRun Disabled (255=all)";  Expected = 255 }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";                    Name = "RequireSecuritySignature";    Label = "SMB Server Signing Required"; Expected = 1 }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";                     Name = "fAllowToGetHelp";             Label = "Remote Assistance Disabled";  Expected = 0 }
)

foreach ($check in $regChecks) {
    $prop = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
    if ($null -eq $prop) {
        Write-Result $check.Label "Not set" "DarkGray"
    } else {
        $current = $prop.($check.Name)
        $match   = $current -eq $check.Expected
        $display = "Value=$current (expected $($check.Expected))"
        $color   = if ($match) { "Green" } else { "Yellow" }
        Write-Result $check.Label $display $color
    }
}


# ============================================================================
# FOOTER
# ============================================================================

Write-Host ""
Write-Host $separator -ForegroundColor Yellow
Write-Host " END OF SNAPSHOT -- $timestamp" -ForegroundColor Yellow
Write-Host $separator -ForegroundColor Yellow
Write-Host ""