<#
.SYNOPSIS
    Module 5: File System Permissions

.DESCRIPTION
    Audits and hardens NTFS permissions on sensitive system directories to prevent
    unauthorized access or modification.

.NOTES
    Project:    SYS-255 Final Project
    Author:     Nad AlDulaimi
    Module:     5 of 9

    Actions performed:
    - Audit permissions on the Windows directory and System32
    - Remove Users and Everyone groups from sensitive directories where inappropriate
    - Verify permissions on the SAM, SECURITY, and SYSTEM registry hive files
    - Restrict permissions on scheduled task directories
    - Audit and document permissions on custom application directories
    - Create a designated tools directory (C:\Tools) with restricted write access
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

function Get-AclReport {
    <#
    .SYNOPSIS
        Returns a formatted string of the ACL entries for a given path.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $lines = $acl.Access | ForEach-Object {
            "  $($_.IdentityReference) | $($_.FileSystemRights) | $($_.AccessControlType) | Inherited: $($_.IsInherited)"
        }
        return ($lines -join "`n")
    } catch {
        return "  ERROR reading ACL: $($_.Exception.Message)"
    }
}

function Remove-ExplicitWriteAccess {
    <#
    .SYNOPSIS
        Removes explicit (non-inherited) Write or FullControl ACEs for a given
        identity from a directory.
    .DESCRIPTION
        Returns a hashtable with Changed and Error properties.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Identity
    )

    $result = @{ Changed = $false; Error = $null }

    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop

        $badRules = $acl.Access | Where-Object {
            $_.IdentityReference -like "*$($Identity.Split('\')[-1])*" -and
            -not $_.IsInherited -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -ne 0
        }

        if ($badRules.Count -eq 0) {
            return $result
        }

        foreach ($rule in $badRules) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }

        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        $result.Changed = $true
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ============================================================================
# ACTION 1: Audit Permissions on Windows Directory and System32
# ============================================================================

$attempted++
Write-HardeningLog "Auditing permissions on Windows and System32 directories" -Level INFO

try {
    $auditPaths = @(
        $env:SystemRoot
        "$env:SystemRoot\System32"
        "$env:SystemRoot\SysWOW64"
        "$env:SystemRoot\System32\drivers"
        "$env:SystemRoot\System32\config"
    )

    $pathsMissing = 0

    foreach ($p in $auditPaths) {
        if (Test-Path -Path $p) {
            Write-HardeningLog "ACL report [$p]:`n$(Get-AclReport $p)" -Level INFO
        } else {
            Write-HardeningLog "Path not found (skipping): $p" -Level WARNING
            $pathsMissing++
        }
    }

    if ($pathsMissing -gt 0) {
        Write-HardeningLog "Windows directory audit complete ($pathsMissing path(s) not found)" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        Write-HardeningLog "Windows directory audit complete" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to audit Windows directory permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Remove Overly Permissive Users/Everyone Entries
# ============================================================================

$attempted++
Write-HardeningLog "Removing explicit Write access for Users/Everyone on sensitive directories" -Level INFO

try {
    $restrictPaths = @(
        "$env:SystemRoot\System32"
        "$env:SystemRoot\SysWOW64"
        "$env:SystemRoot\System32\drivers"
        "$env:SystemRoot\System32\wbem"
    )

    $identities   = @("BUILTIN\Users", "Everyone")
    $removedCount = 0
    $errorCount   = 0

    foreach ($dir in $restrictPaths) {
        if (-not (Test-Path -Path $dir)) {
            Write-HardeningLog "Path not found (skipping): $dir" -Level WARNING
            continue
        }

        foreach ($id in $identities) {
            $result = Remove-ExplicitWriteAccess -Path $dir -Identity $id

            if ($null -ne $result.Error) {
                Write-HardeningLog "Error processing '$id' on '$dir': $($result.Error)" -Level ERROR
                $errorCount++
            } elseif ($result.Changed) {
                Write-HardeningLog "Removed explicit Write access for '$id' on: $dir" -Level INFO
                $removedCount++
            } else {
                Write-HardeningLog "No explicit Write access found for '$id' on: $dir (OK)" -Level INFO
            }
        }
    }

    if ($errorCount -gt 0) {
        Write-HardeningLog "Permission restriction completed with $errorCount error(s)" -Level ERROR
        $failed++
    } elseif ($removedCount -gt 0) {
        Write-HardeningLog "Removed explicit Write access in $removedCount instance(s)" -Level SUCCESS
        $succeeded++
    } else {
        Write-HardeningLog "No overly permissive entries found on sensitive directories" -Level WARNING
        $warnings++
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to process directory permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Verify Permissions on Registry Hive Files
# ============================================================================

$attempted++
Write-HardeningLog "Verifying permissions on registry hive files" -Level INFO

try {
    $hiveFiles = @(
        "$env:SystemRoot\System32\config\SAM"
        "$env:SystemRoot\System32\config\SECURITY"
        "$env:SystemRoot\System32\config\SYSTEM"
        "$env:SystemRoot\System32\config\SOFTWARE"
        "$env:SystemRoot\System32\config\DEFAULT"
    )

    $unexpectedCount = 0
    $missingCount    = 0

    foreach ($hive in $hiveFiles) {
        if (-not (Test-Path -Path $hive)) {
            Write-HardeningLog "Hive file not found (may be locked by OS): $hive" -Level WARNING
            $missingCount++
            continue
        }

        try {
            $acl = Get-Acl -Path $hive -ErrorAction Stop
            Write-HardeningLog "Hive ACL [$hive]:`n$(Get-AclReport $hive)" -Level INFO

            $unexpected = $acl.Access | Where-Object {
                $_.IdentityReference.Value -notmatch "SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER"
            }

            if ($unexpected) {
                foreach ($u in $unexpected) {
                    Write-HardeningLog "Unexpected identity on $hive`: $($u.IdentityReference) ($($u.FileSystemRights))" -Level WARNING
                    $unexpectedCount++
                }
            }
            else {
                Write-HardeningLog "Hive file permissions verified: $hive" -Level INFO
            }
        }
        catch {
            Write-HardeningLog "Could not read ACL for: $hive - $($_.Exception.Message)" -Level WARNING
            $missingCount++
        }
    }

    if ($unexpectedCount -gt 0) {
        Write-HardeningLog "Registry hive audit complete: $unexpectedCount unexpected ACE(s) found and logged" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        Write-HardeningLog "Registry hive file permissions verified successfully" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to verify registry hive permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Restrict Scheduled Task Directory Permissions
# ============================================================================

$attempted++
Write-HardeningLog "Restricting permissions on scheduled task directories" -Level INFO

try {
    $taskDirs   = @(
        "$env:SystemRoot\System32\Tasks"
        "$env:SystemRoot\SysWOW64\Tasks"
    )

    $identities   = @("BUILTIN\Users", "Everyone")
    $removedCount = 0
    $errorCount   = 0

    foreach ($dir in $taskDirs) {
        if (-not (Test-Path -Path $dir)) {
            Write-HardeningLog "Task directory not found (skipping): $dir" -Level WARNING
            continue
        }

        Write-HardeningLog "Task directory ACL [$dir]:`n$(Get-AclReport $dir)" -Level INFO

        foreach ($id in $identities) {
            $result = Remove-ExplicitWriteAccess -Path $dir -Identity $id

            if ($null -ne $result.Error) {
                Write-HardeningLog "Error processing '$id' on '$dir': $($result.Error)" -Level ERROR
                $errorCount++
            } elseif ($result.Changed) {
                Write-HardeningLog "Removed explicit Write access for '$id' on: $dir" -Level INFO
                $removedCount++
            }
        }
    }

    if ($errorCount -gt 0) {
        Write-HardeningLog "Task directory restriction completed with $errorCount error(s)" -Level ERROR
        $failed++
    } elseif ($removedCount -gt 0) {
        Write-HardeningLog "Scheduled task directory permissions restricted ($removedCount change(s))" -Level SUCCESS
        $succeeded++
    } else {
        Write-HardeningLog "Scheduled task directory permissions already appropriately restricted" -Level WARNING
        $warnings++
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to restrict task directory permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Audit Custom Application Directory Permissions
# ============================================================================

$attempted++
Write-HardeningLog "Auditing application directory permissions" -Level INFO

try {
    $appDirs = @(
        $env:ProgramFiles
        ${env:ProgramFiles(x86)}
        $env:ProgramData
    ) | Where-Object { $_ -and (Test-Path -Path $_) }

    $reportDir  = $Script:Config.LogDirectory
    $reportPath = Join-Path -Path $reportDir -ChildPath "Module5_AppDirPermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $csvRows    = [System.Collections.Generic.List[object]]::new()

    foreach ($root in $appDirs) {
        Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dir = $_.FullName
            $acl = Get-Acl -Path $dir -ErrorAction SilentlyContinue
            if ($acl) {
                foreach ($ace in $acl.Access) {
                    $hasWrite = ($ace.FileSystemRights -band `
                        [System.Security.AccessControl.FileSystemRights]::Write) -ne 0
                    $csvRows.Add([PSCustomObject]@{
                        Path           = $dir
                        Identity       = $ace.IdentityReference
                        Rights         = $ace.FileSystemRights
                        Type           = $ace.AccessControlType
                        Inherited      = $ace.IsInherited
                        HasWriteOrMore = $hasWrite
                    })
                }
            }
        }
        Write-HardeningLog "Audited application directory: $root" -Level INFO
    }

    $csvRows | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-HardeningLog "Application directory permission report saved to: $reportPath" -Level SUCCESS
    $succeeded++
} catch {
    Write-HardeningLog "Failed to audit application directory permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Create C:\Tools with Restricted Write Access
# ============================================================================

$attempted++
Write-HardeningLog "Creating C:\Tools directory with restricted permissions" -Level INFO

$toolsDir = "C:\Tools"

try {
    if (-not (Test-Path -Path $toolsDir)) {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
        Write-HardeningLog "Created directory: $toolsDir" -Level INFO
    } else {
        Write-HardeningLog "Directory already exists: $toolsDir" -Level INFO
    }

    # Pre-compute all enum values before use in New-Object constructors.
    # Inline -bor expressions inside comma-separated constructor arguments cause
    # PowerShell's parser to misinterpret operands as argument arrays.
    $acl         = New-Object System.Security.AccessControl.DirectorySecurity
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propFlags   = [System.Security.AccessControl.PropagationFlags]::None
    $allowType   = [System.Security.AccessControl.AccessControlType]::Allow
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $readExec    = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `
                   [System.Security.AccessControl.FileSystemRights]::ListDirectory

    $acl.SetAccessRuleProtection($true, $false)

    # SYSTEM: Full Control
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", $fullControl, $inheritFlags, $propFlags, $allowType
    )))

    # Administrators: Full Control
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", $fullControl, $inheritFlags, $propFlags, $allowType
    )))

    # Users: Read and Execute only
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Users", $readExec, $inheritFlags, $propFlags, $allowType
    )))

    Set-Acl -Path $toolsDir -AclObject $acl -ErrorAction Stop

    Write-HardeningLog "C:\Tools permissions configured (SYSTEM/Administrators: Full Control, Users: Read+Execute)" -Level SUCCESS
    Write-HardeningLog "C:\Tools ACL:`n$(Get-AclReport $toolsDir)" -Level INFO
    $succeeded++
} catch {
    Write-HardeningLog "Failed to configure C:\Tools permissions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 7: Save Permission Snapshot to Log Directory
# ============================================================================

$attempted++
Write-HardeningLog "Saving permission snapshot for key directories" -Level INFO

try {
    $reportDir    = $Script:Config.LogDirectory
    $snapshotPath = Join-Path -Path $reportDir -ChildPath "Module5_PermissionSnapshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $snapshotTargets = @(
        $env:SystemRoot
        "$env:SystemRoot\System32"
        "$env:SystemRoot\System32\config"
        "$env:SystemRoot\System32\Tasks"
        "C:\Tools"
    )

    $snapshot = foreach ($t in $snapshotTargets) {
        if (Test-Path -Path $t) {
            "=== $t ===`n$(Get-AclReport $t)`n"
        }
    }

    $snapshot | Out-File -FilePath $snapshotPath -Encoding UTF8
    Write-HardeningLog "Permission snapshot saved to: $snapshotPath" -Level SUCCESS
    $succeeded++
} catch {
    Write-HardeningLog "Failed to save permission snapshot: $($_.Exception.Message)" -Level ERROR
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