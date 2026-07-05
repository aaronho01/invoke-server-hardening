<#
.SYNOPSIS
    Module 4: Audit Policy and Logging Configuration

.DESCRIPTION
    Configures Windows audit policies to capture security-relevant events in the
    Windows Event Log for monitoring and forensic purposes.

.NOTES
    Project:    SYS-255 Final Project
    Author:     Nad AlDulaimi
    Module:     4 of 9

    Actions performed:
    - Enable audit policy for account logon events (success and failure)
    - Enable audit policy for logon/logoff events (success and failure)
    - Enable audit policy for privilege use (success and failure)
    - Enable audit policy for process creation
    - Enable audit policy for object access on sensitive directories
    - Configure Security log maximum size to 1 GB
    - Set log retention to overwrite as needed
    - Enable command-line logging in process creation events
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

function Invoke-AuditPolicy {
    <#
    .SYNOPSIS
        Calls auditpol.exe to configure a single subcategory and logs the result.
    .DESCRIPTION
        Returns $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Subcategory,

        [Parameter(Mandatory)]
        [ValidateSet("success", "failure", "success,failure")]
        [string]$Setting
    )

    $auditArgs = @("/set", "/subcategory:$Subcategory")
    if ($Setting -match "success") { $auditArgs += "/success:enable" }
    if ($Setting -match "failure") { $auditArgs += "/failure:enable" }

    $output = & auditpol.exe @auditArgs 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-HardeningLog "Configured audit subcategory: $Subcategory ($Setting)" -Level INFO
        return $true
    } else {
        Write-HardeningLog "auditpol failed for subcategory '$Subcategory': $output" -Level ERROR
        return $false
    }
}

# ============================================================================
# ACTION 1: Account Logon Events (success + failure)
# ============================================================================

$attempted++
Write-HardeningLog "Configuring Account Logon audit policies" -Level INFO

try {
    $subcategories = @(
        "Credential Validation"
        "Kerberos Authentication Service"
        "Kerberos Service Ticket Operations"
        "Other Account Logon Events"
    )

    $actionFailed = $false
    foreach ($sub in $subcategories) {
        if (-not (Invoke-AuditPolicy -Subcategory $sub -Setting "success,failure")) {
            $actionFailed = $true
        }
    }

    if ($actionFailed) {
        Write-HardeningLog "One or more Account Logon subcategories could not be configured" -Level ERROR
        $failed++
    } else {
        Write-HardeningLog "Account Logon audit policies configured" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to configure Account Logon audit policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Logon/Logoff Events (success + failure)
# ============================================================================

$attempted++
Write-HardeningLog "Configuring Logon/Logoff audit policies" -Level INFO

try {
    $subcategories = @(
        @{ Name = "Logon";                     Setting = "success,failure" }
        @{ Name = "Logoff";                    Setting = "success" }
        @{ Name = "Account Lockout";           Setting = "success,failure" }
        @{ Name = "Special Logon";             Setting = "success" }
        @{ Name = "Other Logon/Logoff Events"; Setting = "success,failure" }
    )

    $actionFailed = $false
    foreach ($sub in $subcategories) {
        if (-not (Invoke-AuditPolicy -Subcategory $sub.Name -Setting $sub.Setting)) {
            $actionFailed = $true
        }
    }

    if ($actionFailed) {
        Write-HardeningLog "One or more Logon/Logoff subcategories could not be configured" -Level ERROR
        $failed++
    } else {
        Write-HardeningLog "Logon/Logoff audit policies configured" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to configure Logon/Logoff audit policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Privilege Use (success + failure)
# ============================================================================

$attempted++
Write-HardeningLog "Configuring Privilege Use audit policies" -Level INFO

try {
    $subcategories = @(
        @{ Name = "Sensitive Privilege Use";     Setting = "success,failure" }
        @{ Name = "Non Sensitive Privilege Use"; Setting = "failure" }
        @{ Name = "Other Privilege Use Events";  Setting = "success,failure" }
    )

    $actionFailed = $false
    foreach ($sub in $subcategories) {
        if (-not (Invoke-AuditPolicy -Subcategory $sub.Name -Setting $sub.Setting)) {
            $actionFailed = $true
        }
    }

    if ($actionFailed) {
        Write-HardeningLog "One or more Privilege Use subcategories could not be configured" -Level ERROR
        $failed++
    } else {
        Write-HardeningLog "Privilege Use audit policies configured" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to configure Privilege Use audit policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Process Creation and Termination
# ============================================================================

$attempted++
Write-HardeningLog "Configuring Process Tracking audit policies" -Level INFO

try {
    $actionFailed = $false

    if (-not (Invoke-AuditPolicy -Subcategory "Process Creation"    -Setting "success")) { $actionFailed = $true }
    if (-not (Invoke-AuditPolicy -Subcategory "Process Termination" -Setting "success")) { $actionFailed = $true }

    if ($actionFailed) {
        Write-HardeningLog "One or more Process Tracking subcategories could not be configured" -Level ERROR
        $failed++
    } else {
        Write-HardeningLog "Process Tracking audit policies configured" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to configure Process Tracking audit policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Object Access, Account Management, and Policy Change
# ============================================================================

$attempted++
Write-HardeningLog "Configuring Object Access, Account Management, and Policy Change audit policies" -Level INFO

try {
    $subcategories = @(
        @{ Name = "File System";                      Setting = "success,failure" }
        @{ Name = "Registry";                         Setting = "success,failure" }
        @{ Name = "Kernel Object";                    Setting = "failure" }
        @{ Name = "SAM";                              Setting = "success,failure" }
        @{ Name = "Other Object Access Events";       Setting = "failure" }
        @{ Name = "User Account Management";          Setting = "success,failure" }
        @{ Name = "Security Group Management";        Setting = "success,failure" }
        @{ Name = "Other Account Management Events";  Setting = "success,failure" }
        @{ Name = "Audit Policy Change";              Setting = "success,failure" }
        @{ Name = "Authentication Policy Change";     Setting = "success,failure" }
        @{ Name = "Authorization Policy Change";      Setting = "success,failure" }
    )

    $actionFailed = $false
    foreach ($sub in $subcategories) {
        if (-not (Invoke-AuditPolicy -Subcategory $sub.Name -Setting $sub.Setting)) {
            $actionFailed = $true
        }
    }

    if ($actionFailed) {
        Write-HardeningLog "One or more Object Access/Account Management subcategories could not be configured" -Level ERROR
        $failed++
    } else {
        Write-HardeningLog "Object Access, Account Management, and Policy Change audit policies configured" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to configure Object Access audit policies: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Security Log Maximum Size (1 GB)
# ============================================================================

$attempted++
Write-HardeningLog "Setting Security log maximum size to 1 GB" -Level INFO

try {
    # Must be rounded to the nearest 64 KB block
    $maxBytes  = 1GB
    $maxBytes64K = [Math]::Floor($maxBytes / 65536) * 65536

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
    $current = Get-ItemProperty -Path $regPath -Name "MaxSize" -ErrorAction SilentlyContinue

    if ($null -ne $current -and $current.MaxSize -eq $maxBytes64K) {
        Write-HardeningLog "Security log MaxSize already set to $maxBytes64K bytes (~1 GB)" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        Set-ItemProperty -Path $regPath -Name "MaxSize" -Value $maxBytes64K -Type DWord -Force
        Write-HardeningLog "Security log MaxSize set to $maxBytes64K bytes (~1 GB)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to set Security log MaxSize: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 7: Log Retention - Overwrite as Needed
# ============================================================================

$attempted++
Write-HardeningLog "Setting Security log retention to overwrite as needed" -Level INFO

try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
    $current = Get-ItemProperty -Path $regPath -Name "Retention" -ErrorAction SilentlyContinue

    # Retention = 0 means overwrite as needed
    if ($null -ne $current -and $current.Retention -eq 0) {
        Write-HardeningLog "Security log retention already set to overwrite as needed" -Level WARNING
        $warnings++
        $succeeded++
    }
    else {
        Set-ItemProperty -Path $regPath -Name "Retention" -Value 0 -Type DWord -Force
        Write-HardeningLog "Security log retention set to overwrite as needed" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to set Security log retention: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 8: Enable Command-Line Logging in Process Creation Events
# ============================================================================

$attempted++
Write-HardeningLog "Enabling command-line logging in process creation events (Event ID 4688)" -Level INFO

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-HardeningLog "Created registry path for process creation audit policy" -Level INFO
    }

    $current = Get-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue

    if ($null -ne $current -and $current.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Write-HardeningLog "Command-line logging already enabled" -Level WARNING
        $warnings++
        $succeeded++
    }
    else {
        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
        Write-HardeningLog "Command-line logging enabled (ProcessCreationIncludeCmdLine_Enabled = 1)" -Level SUCCESS
        $succeeded++
    }
} catch {
    Write-HardeningLog "Failed to enable command-line logging: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 9: Capture Final Audit Policy State for Documentation
# ============================================================================

$attempted++
Write-HardeningLog "Saving final audit policy state to report file" -Level INFO

try {
    $reportDir  = $Script:Config.LogDirectory
    $reportPath = Join-Path -Path $reportDir -ChildPath "Module4_AuditPolicy_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $auditReport = & auditpol.exe /get /category:* 2>&1
    $auditReport | Out-File -FilePath $reportPath -Encoding UTF8

    Write-HardeningLog "Audit policy report saved to: $reportPath" -Level SUCCESS
    $succeeded++
} catch {
    Write-HardeningLog "Failed to save audit policy report: $($_.Exception.Message)" -Level ERROR
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