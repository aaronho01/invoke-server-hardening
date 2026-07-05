<#
.SYNOPSIS
    Module 9: Registry Security Hardening
    
.DESCRIPTION
    Applies security-focused registry modifications to disable dangerous default
    behaviors and harden system configuration.
    
.NOTES
    Project:    SYS-255 Final Project
    Author:     Aaron Ho
    Module:     9 of 9
    
    Actions performed:
    - Disable AutoRun and AutoPlay for all drive types
    - Restrict anonymous enumeration of SAM accounts and shares
    - Enable LSASS protection (RunAsPPL)
    - Disable WDigest credential caching
    - Disable remote assistance solicitation
    - Restrict NTLM authentication where possible
    - Enable SMB signing
    - Disable storing LAN Manager hash values
#>

# ============================================================================
# INITIALIZATION
# ============================================================================

$attempted = 0
$succeeded = 0
$warnings  = 0
$failed    = 0

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Sets a registry value, creating the path if necessary.
    .DESCRIPTION
        Returns a hashtable with Changed, AlreadySet, and Error properties.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        $Value,
        
        [Parameter(Mandatory)]
        [ValidateSet("DWord", "QWord", "String", "ExpandString", "MultiString", "Binary")]
        [string]$Type,
        
        [string]$Description = ""
    )
    
    $result = @{
        Changed    = $false
        AlreadySet = $false
        Error      = $null
    }
    
    try {
        # Create path if it doesn't exist
        if (-not (Test-Path -Path $Path)) {
            $null = New-Item -Path $Path -Force
            Write-HardeningLog "Created registry path: $Path" -Level INFO
        }
        
        # Check current value
        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($null -ne $currentValue -and $currentValue.$Name -eq $Value) {
            $result.AlreadySet = $true
            return $result
        }
        
        # Set the value
        $null = Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        $result.Changed = $true
        
        # Verify the change
        $newValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($newValue.$Name -ne $Value) {
            $result.Error = "Value verification failed"
            $result.Changed = $false
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# ACTION 1: Disable AutoRun and AutoPlay
# ============================================================================

$attempted++
Write-HardeningLog "Disabling AutoRun and AutoPlay for all drive types" -Level INFO

try {
    $autorunChanges = 0
    $autorunAlready = 0
    
    # Disable AutoRun for all drives (value 255 = 0xFF = all drive types)
    $result = Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoDriveTypeAutoRun" `
        -Value 255 `
        -Type DWord
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "Disabled AutoRun for all drive types" -Level INFO
        $autorunChanges++
    }
    else {
        $autorunAlready++
    }
    
    # Disable AutoPlay
    $result = Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoAutorun" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "Disabled AutoPlay" -Level INFO
        $autorunChanges++
    }
    else {
        $autorunAlready++
    }
    
    # Disable AutoRun commands
    $result = Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "HonorAutorunSetting" `
        -Value 1 `
        -Type DWord
    
    if ($result.Changed) { $autorunChanges++ } else { $autorunAlready++ }
    
    if ($autorunChanges -gt 0) {
        Write-HardeningLog "AutoRun/AutoPlay disabled ($autorunChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "AutoRun/AutoPlay already disabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable AutoRun/AutoPlay: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Restrict Anonymous Enumeration of SAM Accounts and Shares
# ============================================================================

$attempted++
Write-HardeningLog "Restricting anonymous enumeration of SAM accounts and shares" -Level INFO

try {
    $anonChanges = 0
    $anonAlready = 0
    
    # Restrict anonymous enumeration of SAM accounts
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymousSAM" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Restricted anonymous SAM enumeration" -Level INFO
        $anonChanges++
    }
    else { $anonAlready++ }
    
    # Restrict anonymous enumeration of shares
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Restricted anonymous share enumeration" -Level INFO
        $anonChanges++
    }
    else { $anonAlready++ }
    
    # Disable anonymous SID/Name translation
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "TurnOffAnonymousBlock" `
        -Value 1 `
        -Type DWord
    
    if ($result.Changed) { $anonChanges++ } else { $anonAlready++ }
    
    if ($anonChanges -gt 0) {
        Write-HardeningLog "Anonymous enumeration restricted ($anonChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Anonymous enumeration already restricted" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to restrict anonymous enumeration: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Enable LSASS Protection (RunAsPPL)
# ============================================================================

$attempted++
Write-HardeningLog "Enabling LSASS protection (RunAsPPL)" -Level INFO

try {
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPL" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "LSASS protection enabled (requires reboot)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "LSASS protection already enabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to enable LSASS protection: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Disable WDigest Credential Caching
# ============================================================================

$attempted++
Write-HardeningLog "Disabling WDigest credential caching" -Level INFO

try {
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" `
        -Value 0 `
        -Type DWord
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "WDigest credential caching disabled" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "WDigest credential caching already disabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable WDigest: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Disable Remote Assistance Solicitation
# ============================================================================

$attempted++
Write-HardeningLog "Disabling remote assistance solicitation" -Level INFO

try {
    $raChanges = 0
    $raAlready = 0
    
    # Disable solicited remote assistance
    $result = Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fAllowToGetHelp" `
        -Value 0 `
        -Type DWord
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Disabled solicited remote assistance" -Level INFO
        $raChanges++
    }
    else { $raAlready++ }
    
    # Disable unsolicited remote assistance
    $result = Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fAllowUnsolicited" `
        -Value 0 `
        -Type DWord
    
    if ($result.Changed) {
        Write-HardeningLog "Disabled unsolicited remote assistance" -Level INFO
        $raChanges++
    }
    else { $raAlready++ }
    
    if ($raChanges -gt 0) {
        Write-HardeningLog "Remote assistance disabled ($raChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Remote assistance already disabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable remote assistance: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Restrict NTLM Authentication
# ============================================================================

$attempted++
Write-HardeningLog "Configuring NTLM authentication restrictions" -Level INFO

try {
    $ntlmChanges = 0
    $ntlmAlready = 0
    
    # Restrict NTLM: Audit incoming NTLM traffic
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "AuditReceivingNTLMTraffic" `
        -Value 2 `
        -Type DWord
    
    if ($result.Changed) {
        Write-HardeningLog "Enabled NTLM incoming traffic auditing" -Level INFO
        $ntlmChanges++
    }
    else { $ntlmAlready++ }
    
    # Restrict NTLM: Outgoing NTLM traffic to remote servers (Audit all)
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
        -Name "RestrictSendingNTLMTraffic" `
        -Value 1 `
        -Type DWord
    
    if ($result.Changed) {
        Write-HardeningLog "Enabled NTLM outgoing traffic auditing" -Level INFO
        $ntlmChanges++
    }
    else { $ntlmAlready++ }
    
    # Set LAN Manager authentication level to NTLMv2 only
    # Value 5 = Send NTLMv2 response only, refuse LM & NTLM
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" `
        -Value 5 `
        -Type DWord
    
    if ($result.Changed) {
        Write-HardeningLog "Set LAN Manager to NTLMv2 only" -Level INFO
        $ntlmChanges++
    }
    else { $ntlmAlready++ }
    
    if ($ntlmChanges -gt 0) {
        Write-HardeningLog "NTLM restrictions configured ($ntlmChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "NTLM restrictions already configured" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to configure NTLM restrictions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 7: Enable SMB Signing
# ============================================================================

$attempted++
Write-HardeningLog "Enabling SMB signing requirements" -Level INFO

try {
    $smbChanges = 0
    $smbAlready = 0
    
    # SMB Server: Require signing
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RequireSecuritySignature" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "SMB Server: Required signing enabled" -Level INFO
        $smbChanges++
    }
    else { $smbAlready++ }
    
    # SMB Server: Enable signing
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "EnableSecuritySignature" `
        -Value 1 `
        -Type DWord
    
    if ($result.Changed) { $smbChanges++ } else { $smbAlready++ }
    
    # SMB Client: Require signing
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "RequireSecuritySignature" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "SMB Client: Required signing enabled" -Level INFO
        $smbChanges++
    }
    else { $smbAlready++ }
    
    # SMB Client: Enable signing
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnableSecuritySignature" `
        -Value 1 `
        -Type DWord
    
    if ($result.Changed) { $smbChanges++ } else { $smbAlready++ }
    
    if ($smbChanges -gt 0) {
        Write-HardeningLog "SMB signing enabled ($smbChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "SMB signing already enabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to configure SMB signing: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 8: Disable LAN Manager Hash Storage
# ============================================================================

$attempted++
Write-HardeningLog "Disabling LAN Manager hash storage" -Level INFO

try {
    $result = Set-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "NoLMHash" `
        -Value 1 `
        -Type DWord
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "LAN Manager hash storage disabled" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "LAN Manager hash storage already disabled" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable LM hash storage: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 9: Verify Registry Hardening
# ============================================================================

$attempted++
Write-HardeningLog "Verifying registry hardening settings" -Level INFO

try {
    $verifyFailed = 0
    
    # Spot check critical settings
    $criticalSettings = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; Expected = 1 }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Expected = 0 }
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Expected = 1 }
    )
    
    foreach ($setting in $criticalSettings) {
        $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
        if ($null -eq $value -or $value.$($setting.Name) -ne $setting.Expected) {
            Write-HardeningLog "Verification failed: $($setting.Path)\$($setting.Name)" -Level ERROR
            $verifyFailed++
        }
    }
    
    if ($verifyFailed -eq 0) {
        Write-HardeningLog "Registry hardening verified successfully" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Registry verification: $verifyFailed setting(s) not applied correctly" -Level ERROR
        $failed++
    }
}
catch {
    Write-HardeningLog "Failed to verify registry settings: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# RETURN RESULTS
# ============================================================================

$moduleResult = @{
    Success          = ($failed -eq 0)
    ActionsAttempted = $attempted
    ActionsSucceeded = $succeeded
    ActionsWarning   = $warnings
    ActionsFailed    = $failed
}

return $moduleResult