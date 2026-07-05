<#
.SYNOPSIS
    Module 3: Local Group Membership Audit

.DESCRIPTION
    Audits and restricts membership in privileged local groups to ensure only
    authorized accounts have elevated access. Logs all findings and removes
    any unauthorized accounts from the Administrators group.

.NOTES
    Project:    SYS-255 Final Project
    Author:     Andrew Zombek
    Module:     3 of 9

    Actions performed:
    - Enumerate and log current Administrators group membership
    - Remove unauthorized accounts from the Administrators group
    - Audit membership of Remote Desktop Users group
    - Audit membership of Backup Operators group
    - Audit membership of Power Users group
    - Verify final Administrators group membership
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

# Accounts that are authorized to remain in the Administrators group.
# These should match the renamed Administrator account and the new admin
# user created by Module 1.
$Config = @{
    AuthorizedAdmins = @("Andrew", "Aaron")
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Resolve-AccountName {
    <#
    .SYNOPSIS
        Resolves the current name of a local account by its SID.
    .DESCRIPTION
        Returns the current local user name if found, otherwise falls back to
        stripping the domain prefix from the member's display name. This avoids
        failures caused by stale display names when an account has been renamed
        by an earlier module.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$SID
    )

    $localUser = Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $SID }

    if ($null -ne $localUser) {
        return $localUser.Name
    }

    # SID belongs to a group or domain account - return $null to signal that
    return $null
}

# ============================================================================
# ACTION 1: Audit and Log Administrators Group Membership
# ============================================================================

$attempted++
Write-HardeningLog "Auditing current Administrators group membership" -Level INFO

try {
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    if ($adminMembers.Count -eq 0) {
        Write-HardeningLog "Administrators group has no members" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        foreach ($member in $adminMembers) {
            # Resolve current name via SID to handle renamed accounts
            $resolvedName = Resolve-AccountName -SID $member.SID
            $displayName  = if ($resolvedName) { $resolvedName } else { $member.Name -replace "^.+\\\s*", "" }
            Write-HardeningLog "Administrators member: $displayName (SID: $($member.SID)) [Type: $($member.ObjectClass), Source: $($member.PrincipalSource)]" -Level INFO
        }
        Write-HardeningLog "Administrators group audit complete ($($adminMembers.Count) member(s) found)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to audit Administrators group: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Remove Unauthorized Accounts from Administrators
# ============================================================================

$attempted++
Write-HardeningLog "Checking Administrators group for unauthorized accounts" -Level INFO

try {
    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $removedCount  = 0
    $skippedCount  = 0

    foreach ($member in $adminMembers) {
        # Resolve the current account name via SID. If Module 1 renamed the
        # built-in Administrator account, the SID remains the same but the
        # display name returned by Get-LocalGroupMember may be stale. Using
        # the SID for both name resolution and removal avoids the
        # "principal not found" error that occurs when removing by stale name.
        $resolvedName = Resolve-AccountName -SID $member.SID
        $accountName  = if ($resolvedName) { $resolvedName } else { $member.Name -replace "^.+\\\s*", "" }

        $isAuthorized = $Config.AuthorizedAdmins | Where-Object { $_ -eq $accountName }

        if ($null -ne $isAuthorized) {
            Write-HardeningLog "Authorized account retained in Administrators: $accountName (SID: $($member.SID))" -Level INFO
            $skippedCount++
        } else {
            Write-HardeningLog "Unauthorized account found in Administrators: $accountName (SID: $($member.SID)) - removing" -Level WARNING
            # Remove by SID to avoid failures from stale or unresolvable display names
            Remove-LocalGroupMember -Group "Administrators" -Member $member.SID -ErrorAction Stop
            Write-HardeningLog "Removed unauthorized account from Administrators: $accountName" -Level SUCCESS
            $removedCount++
        }
    }

    if ($removedCount -gt 0) {
        Write-HardeningLog "Removed $removedCount unauthorized account(s) from Administrators" -Level SUCCESS
        $succeeded++
    } else {
        Write-HardeningLog "No unauthorized accounts found in Administrators group ($skippedCount authorized member(s) retained)" -Level WARNING
        $warnings++
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to process Administrators group membership: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Audit Remote Desktop Users Group
# ============================================================================

$attempted++
Write-HardeningLog "Auditing Remote Desktop Users group membership" -Level INFO

try {
    $rdpMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue

    if ($null -eq $rdpMembers -or $rdpMembers.Count -eq 0) {
        Write-HardeningLog "Remote Desktop Users group is empty" -Level INFO
        $succeeded++
    } else {
        foreach ($member in $rdpMembers) {
            Write-HardeningLog "Remote Desktop Users member: $($member.Name) [Type: $($member.ObjectClass)]" -Level INFO
        }
        Write-HardeningLog "Remote Desktop Users audit complete ($($rdpMembers.Count) member(s) logged)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to audit Remote Desktop Users group: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Audit Backup Operators Group
# ============================================================================

$attempted++
Write-HardeningLog "Auditing Backup Operators group membership" -Level INFO

try {
    $backupMembers = Get-LocalGroupMember -Group "Backup Operators" -ErrorAction SilentlyContinue

    if ($null -eq $backupMembers -or $backupMembers.Count -eq 0) {
        Write-HardeningLog "Backup Operators group is empty" -Level INFO
        $succeeded++
    } else {
        foreach ($member in $backupMembers) {
            Write-HardeningLog "Backup Operators member: $($member.Name) [Type: $($member.ObjectClass)]" -Level INFO
        }
        Write-HardeningLog "Backup Operators audit complete ($($backupMembers.Count) member(s) logged)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to audit Backup Operators group: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Audit Power Users Group
# ============================================================================

$attempted++
Write-HardeningLog "Auditing Power Users group membership" -Level INFO

try {
    $powerMembers = Get-LocalGroupMember -Group "Power Users" -ErrorAction SilentlyContinue

    if ($null -eq $powerMembers -or $powerMembers.Count -eq 0) {
        Write-HardeningLog "Power Users group is empty" -Level INFO
        $succeeded++
    } else {
        foreach ($member in $powerMembers) {
            Write-HardeningLog "Power Users member: $($member.Name) [Type: $($member.ObjectClass)]" -Level INFO
        }
        Write-HardeningLog "Power Users audit complete ($($powerMembers.Count) member(s) logged)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to audit Power Users group: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Verify Final Administrators Group Membership
# ============================================================================

$attempted++
Write-HardeningLog "Verifying final Administrators group membership" -Level INFO

try {
    $verifyFailed = 0
    $finalMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    # Build a list of resolved current names from SIDs so that renamed accounts
    # are compared correctly against AuthorizedAdmins
    $finalNames = foreach ($member in $finalMembers) {
        $resolved = Resolve-AccountName -SID $member.SID
        if ($resolved) { $resolved } else { $member.Name -replace "^.+\\\s*", "" }
    }

    # Verify each authorized admin is present
    foreach ($authorizedAccount in $Config.AuthorizedAdmins) {
        if ($finalNames -notcontains $authorizedAccount) {
            Write-HardeningLog "Verification failed: authorized account '$authorizedAccount' is missing from Administrators" -Level ERROR
            $verifyFailed++
        }
    }

    # Verify no unauthorized accounts remain
    foreach ($name in $finalNames) {
        $isAuthorized = $Config.AuthorizedAdmins | Where-Object { $_ -eq $name }
        if ($null -eq $isAuthorized) {
            Write-HardeningLog "Verification failed: unauthorized account '$name' still present in Administrators" -Level ERROR
            $verifyFailed++
        }
    }

    if ($verifyFailed -eq 0) {
        Write-HardeningLog "Administrators group verified successfully: $($finalNames -join ', ')" -Level SUCCESS
        $succeeded++
    } else {
        Write-HardeningLog "Administrators group verification: $verifyFailed check(s) failed" -Level ERROR
        $failed++
    }
} catch {
    Write-HardeningLog "Failed to verify Administrators group: $($_.Exception.Message)" -Level ERROR
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