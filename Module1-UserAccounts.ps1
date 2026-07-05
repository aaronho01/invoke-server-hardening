<#
.SYNOPSIS
    Module 1: User Account Hardening
    
.DESCRIPTION
    Secures local user accounts by disabling insecure built-in accounts,
    renaming the Administrator account, and creating a dedicated admin user.
    
.NOTES
    Project:    SYS-255 Final Project
    Author:     Andrew Zombek
    Module:     1 of 9
    
    Actions performed:
    - Disable the Guest account
    - Rename the built-in Administrator account
    - Create a new administrative user account
    - Disable DefaultAccount and WDAGUtilityAccount
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
    AdminRename    = "Andrew"
    NewAdminUser   = "Aaron"
    NewAdminPass   = "CHANGE_ME_BEFORE_USE"
    NewAdminFull   = "Admin Account"
}

# ============================================================================
# ACTION 1: Disable Guest Account
# ============================================================================

$attempted++
Write-HardeningLog "Disabling Guest account" -Level INFO

try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    if ($null -eq $guest) {
        Write-HardeningLog "Guest account not found on this system" -Level WARNING
        $warnings++
        $succeeded++
    }
    elseif (-not $guest.Enabled) {
        Write-HardeningLog "Guest account already disabled" -Level WARNING
        $warnings++
        $succeeded++
    }
    else {
        Disable-LocalUser -Name "Guest" -ErrorAction Stop
        Write-HardeningLog "Guest account disabled" -Level SUCCESS
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable Guest account: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Rename Built-in Administrator Account
# ============================================================================

$attempted++
Write-HardeningLog "Renaming built-in Administrator account to '$($Config.AdminRename)'" -Level INFO

try {
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    $renamed = Get-LocalUser -Name $Config.AdminRename -ErrorAction SilentlyContinue
    
    if ($null -ne $renamed) {
        Write-HardeningLog "Administrator account already renamed to '$($Config.AdminRename)'" -Level WARNING
        $warnings++
        $succeeded++
    }
    elseif ($null -eq $admin) {
        Write-HardeningLog "Built-in Administrator account not found (may already be renamed)" -Level WARNING
        $warnings++
        $succeeded++
    }
    else {
        Rename-LocalUser -Name "Administrator" -NewName $Config.AdminRename -ErrorAction Stop
        Write-HardeningLog "Administrator account renamed to '$($Config.AdminRename)'" -Level SUCCESS
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to rename Administrator account: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Create New Administrative User
# ============================================================================

$attempted++
Write-HardeningLog "Creating new administrative user '$($Config.NewAdminUser)'" -Level INFO

try {
    $existingUser = Get-LocalUser -Name $Config.NewAdminUser -ErrorAction SilentlyContinue
    
    if ($null -ne $existingUser) {
        Write-HardeningLog "User '$($Config.NewAdminUser)' already exists" -Level WARNING
        
        # Verify user is in Administrators group
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $isAdmin = $adminGroup | Where-Object { $_.Name -like "*\$($Config.NewAdminUser)" }
        
        if ($null -eq $isAdmin) {
            Add-LocalGroupMember -Group "Administrators" -Member $Config.NewAdminUser -ErrorAction Stop
            Write-HardeningLog "Added existing user '$($Config.NewAdminUser)' to Administrators group" -Level INFO
        }
        
        $warnings++
        $succeeded++
    }
    else {
        # Create the new user
        $securePassword = ConvertTo-SecureString $Config.NewAdminPass -AsPlainText -Force
        New-LocalUser -Name $Config.NewAdminUser `
                      -Password $securePassword `
                      -FullName $Config.NewAdminFull `
                      -Description "Hardening script admin account" `
                      -PasswordNeverExpires:$false `
                      -ErrorAction Stop | Out-Null
        
        # Add to Administrators group
        Add-LocalGroupMember -Group "Administrators" -Member $Config.NewAdminUser -ErrorAction Stop
        
        Write-HardeningLog "Created administrative user '$($Config.NewAdminUser)' and added to Administrators group" -Level SUCCESS
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to create administrative user: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Disable Default System Accounts
# ============================================================================

$attempted++
Write-HardeningLog "Disabling default system accounts (DefaultAccount, WDAGUtilityAccount)" -Level INFO

try {
    $accountsDisabled = 0
    $accountsAlready = 0
    $accountsNotFound = 0
    
    $accountsToDisable = @("DefaultAccount", "WDAGUtilityAccount")
    
    foreach ($accountName in $accountsToDisable) {
        $account = Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue
        
        if ($null -eq $account) {
            Write-HardeningLog "$accountName not found on this system" -Level INFO
            $accountsNotFound++
        }
        elseif (-not $account.Enabled) {
            $accountsAlready++
        }
        else {
            Disable-LocalUser -Name $accountName -ErrorAction Stop
            Write-HardeningLog "Disabled $accountName" -Level INFO
            $accountsDisabled++
        }
    }
    
    if ($accountsDisabled -gt 0) {
        Write-HardeningLog "Default accounts disabled ($accountsDisabled accounts)" -Level SUCCESS
        $succeeded++
    }
    elseif ($accountsAlready -eq $accountsToDisable.Count -or ($accountsAlready + $accountsNotFound) -eq $accountsToDisable.Count) {
        Write-HardeningLog "Default accounts already disabled or not present" -Level WARNING
        $warnings++
        $succeeded++
    }
    else {
        Write-HardeningLog "Default accounts processed ($accountsAlready already disabled, $accountsNotFound not found)" -Level SUCCESS
        $succeeded++
    }
}
catch {
    Write-HardeningLog "Failed to disable default accounts: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Verify User Account Hardening
# ============================================================================

$attempted++
Write-HardeningLog "Verifying user account hardening" -Level INFO

try {
    $verifyFailed = 0
    
    # Check Guest is disabled
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -ne $guest -and $guest.Enabled) {
        Write-HardeningLog "Verification failed: Guest account is still enabled" -Level ERROR
        $verifyFailed++
    }
    
    # Check Administrator was renamed (original name should not exist)
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    $renamed = Get-LocalUser -Name $Config.AdminRename -ErrorAction SilentlyContinue
    if ($null -ne $admin -and $null -eq $renamed) {
        Write-HardeningLog "Verification failed: Administrator account not renamed" -Level ERROR
        $verifyFailed++
    }
    
    # Check new admin user exists and is in Administrators group
    $newAdmin = Get-LocalUser -Name $Config.NewAdminUser -ErrorAction SilentlyContinue
    if ($null -eq $newAdmin) {
        Write-HardeningLog "Verification failed: Admin user '$($Config.NewAdminUser)' not found" -Level ERROR
        $verifyFailed++
    }
    else {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $isAdmin = $adminGroup | Where-Object { $_.Name -like "*\$($Config.NewAdminUser)" }
        if ($null -eq $isAdmin) {
            Write-HardeningLog "Verification failed: '$($Config.NewAdminUser)' not in Administrators group" -Level ERROR
            $verifyFailed++
        }
    }
    
    if ($verifyFailed -eq 0) {
        Write-HardeningLog "User account hardening verified successfully" -Level SUCCESS
        $succeeded++
    }
    else {
        Write-HardeningLog "User account verification: $verifyFailed check(s) failed" -Level ERROR
        $failed++
    }
}
catch {
    Write-HardeningLog "Failed to verify user account settings: $($_.Exception.Message)" -Level ERROR
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