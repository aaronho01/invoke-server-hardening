<#
.SYNOPSIS
    Module 2: Password and Lockout Policy
    
.DESCRIPTION
    Configures secure password requirements and account lockout policies
    to protect against brute-force attacks and weak credentials.
    
.NOTES
    Project:    SYS-255 Final Project
    Author:     Aaron Ho
    Module:     2 of 9
    
    Actions performed:
    - Set minimum password length to 14 characters
    - Set maximum password age to 90 days
    - Set minimum password age to 1 day
    - Enforce password history of 24 passwords
    - Configure account lockout threshold to 5 attempts
    - Set account lockout duration to 30 minutes
    - Set lockout observation window to 30 minutes
#>

# ============================================================================
# INITIALIZATION
# ============================================================================

$attempted = 0
$succeeded = 0
$warnings  = 0
$failed    = 0

# ============================================================================
# CONFIGURATION
# ============================================================================

$Config = @{
    MinPasswordLength    = 14
    MaxPasswordAge       = 90
    MinPasswordAge       = 1
    PasswordHistory      = 24
    LockoutThreshold     = 5
    LockoutDuration      = 30
    LockoutWindow        = 30
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-NetAccountsSettings {
    <#
    .SYNOPSIS
        Parses the output of 'net accounts' into a hashtable.
    #>
    
    $output = net accounts 2>&1
    $settings = @{}
    
    foreach ($line in $output) {
        if ($line -match "^(.+?):\s+(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $settings[$key] = $value
        }
    }
    
    return $settings
}

function Set-NetAccountSetting {
    <#
    .SYNOPSIS
        Sets a net accounts setting and verifies the change.
    .DESCRIPTION
        Returns a hashtable with Changed, AlreadySet, and Error properties.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Parameter,
        
        [Parameter(Mandatory)]
        [int]$Value,
        
        [Parameter(Mandatory)]
        [string]$SettingName,
        
        [string]$ExpectedDisplay = $null
    )
    
    $result = @{
        Changed    = $false
        AlreadySet = $false
        Error      = $null
    }
    
    try {
        # Get current settings
        $before = Get-NetAccountsSettings
        $currentValue = $before[$SettingName]
        
        # Determine expected display value for comparison
        if ($null -eq $ExpectedDisplay) {
            $ExpectedDisplay = $Value.ToString()
        }
        
        # Check if already set (handle "Never" for unlimited values)
        if ($currentValue -eq $ExpectedDisplay -or 
            ($Value -eq 0 -and $currentValue -eq "Never") -or
            $currentValue -match "^\s*$Value\s*$") {
            $result.AlreadySet = $true
            return $result
        }
        
        # Apply the setting
        $netOutput = net accounts $Parameter`:$Value 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            $result.Error = "net accounts returned exit code $LASTEXITCODE"
            return $result
        }
        
        # Verify the change
        $after = Get-NetAccountsSettings
        $newValue = $after[$SettingName]
        
        if ($newValue -eq $ExpectedDisplay -or 
            $newValue -match "^\s*$Value\s*$" -or
            ($Value -eq 0 -and $newValue -eq "Never")) {
            $result.Changed = $true
        }
        else {
            $result.Error = "Verification failed: expected '$ExpectedDisplay', got '$newValue'"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# ACTION 1: Configure Password Length Requirements
# ============================================================================

$attempted++
Write-HardeningLog "Configuring minimum password length to $($Config.MinPasswordLength) characters" -Level INFO

try {
    $result = Set-NetAccountSetting `
        -Parameter "/minpwlen" `
        -Value $Config.MinPasswordLength `
        -SettingName "Minimum password length"
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "Minimum password length set to $($Config.MinPasswordLength) characters" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Minimum password length already set to $($Config.MinPasswordLength)" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to set minimum password length: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Configure Password Age Policies
# ============================================================================

$attempted++
Write-HardeningLog "Configuring password age policies" -Level INFO

try {
    $ageChanges = 0
    $ageAlready = 0
    
    # Maximum password age (90 days)
    $result = Set-NetAccountSetting `
        -Parameter "/maxpwage" `
        -Value $Config.MaxPasswordAge `
        -SettingName "Maximum password age (days)"
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Maximum password age set to $($Config.MaxPasswordAge) days" -Level INFO
        $ageChanges++
    }
    else { $ageAlready++ }
    
    # Minimum password age (1 day)
    $result = Set-NetAccountSetting `
        -Parameter "/minpwage" `
        -Value $Config.MinPasswordAge `
        -SettingName "Minimum password age (days)"
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Minimum password age set to $($Config.MinPasswordAge) day(s)" -Level INFO
        $ageChanges++
    }
    else { $ageAlready++ }
    
    if ($ageChanges -gt 0) {
        Write-HardeningLog "Password age policies configured ($ageChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Password age policies already configured" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to configure password age policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Configure Password History
# ============================================================================

$attempted++
Write-HardeningLog "Configuring password history to $($Config.PasswordHistory) passwords" -Level INFO

try {
    $result = Set-NetAccountSetting `
        -Parameter "/uniquepw" `
        -Value $Config.PasswordHistory `
        -SettingName "Length of password history maintained"
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "Password history set to $($Config.PasswordHistory) passwords" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Password history already set to $($Config.PasswordHistory)" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to set password history: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Configure Account Lockout Threshold
# ============================================================================

$attempted++
Write-HardeningLog "Configuring account lockout threshold to $($Config.LockoutThreshold) attempts" -Level INFO

try {
    $result = Set-NetAccountSetting `
        -Parameter "/lockoutthreshold" `
        -Value $Config.LockoutThreshold `
        -SettingName "Lockout threshold"
    
    if ($result.Error) {
        throw $result.Error
    }
    elseif ($result.Changed) {
        Write-HardeningLog "Account lockout threshold set to $($Config.LockoutThreshold) attempts" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Account lockout threshold already set to $($Config.LockoutThreshold)" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to set lockout threshold: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Configure Account Lockout Duration and Window
# ============================================================================

$attempted++
Write-HardeningLog "Configuring account lockout duration and observation window" -Level INFO

try {
    $lockoutChanges = 0
    $lockoutAlready = 0
    
    # Lockout duration (30 minutes)
    $result = Set-NetAccountSetting `
        -Parameter "/lockoutduration" `
        -Value $Config.LockoutDuration `
        -SettingName "Lockout duration (minutes)"
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Lockout duration set to $($Config.LockoutDuration) minutes" -Level INFO
        $lockoutChanges++
    }
    else { $lockoutAlready++ }
    
    # Lockout observation window (30 minutes)
    $result = Set-NetAccountSetting `
        -Parameter "/lockoutwindow" `
        -Value $Config.LockoutWindow `
        -SettingName "Lockout observation window (minutes)"
    
    if ($result.Error) { throw $result.Error }
    if ($result.Changed) {
        Write-HardeningLog "Lockout observation window set to $($Config.LockoutWindow) minutes" -Level INFO
        $lockoutChanges++
    }
    else { $lockoutAlready++ }
    
    if ($lockoutChanges -gt 0) {
        Write-HardeningLog "Lockout timing configured ($lockoutChanges settings changed)" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Lockout timing already configured" -Level WARNING
        $warnings++
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to configure lockout timing: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Verify Password and Lockout Policies
# ============================================================================

$attempted++
Write-HardeningLog "Verifying password and lockout policy settings" -Level INFO

try {
    $verifyFailed = 0
    $settings = Get-NetAccountsSettings
    
    # Verify minimum password length
    $minLen = $settings["Minimum password length"]
    if ($minLen -notmatch "^\s*$($Config.MinPasswordLength)\s*$") {
        Write-HardeningLog "Verification failed: Minimum password length is '$minLen', expected '$($Config.MinPasswordLength)'" -Level ERROR
        $verifyFailed++
    }
    
    # Verify lockout threshold
    $threshold = $settings["Lockout threshold"]
    if ($threshold -notmatch "^\s*$($Config.LockoutThreshold)\s*$") {
        Write-HardeningLog "Verification failed: Lockout threshold is '$threshold', expected '$($Config.LockoutThreshold)'" -Level ERROR
        $verifyFailed++
    }
    
    # Verify password history
    $history = $settings["Length of password history maintained"]
    if ($history -notmatch "^\s*$($Config.PasswordHistory)\s*$") {
        Write-HardeningLog "Verification failed: Password history is '$history', expected '$($Config.PasswordHistory)'" -Level ERROR
        $verifyFailed++
    }
    
    if ($verifyFailed -eq 0) {
        Write-HardeningLog "Password and lockout policies verified successfully" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "Policy verification: $verifyFailed setting(s) not applied correctly" -Level ERROR
        $failed++
    }
}
catch {
    Write-HardeningLog "Failed to verify policy settings: $($_.Exception.Message)" -Level ERROR
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