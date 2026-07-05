<#
.SYNOPSIS
    Module 7: Service Hardening
    
.DESCRIPTION
    Disables unnecessary Windows services that expand the attack surface and are
    not required for the server's intended function.
    
.NOTES
    Project:    SYS-255 Final Project
    Author:     Aaron Ho
    Module:     7 of 9
    
    Actions performed:
    - Disable Remote Registry service
    - Disable Print Spooler service (if not a print server)
    - Disable Windows Remote Management if not required
    - Disable Xbox-related services
    - Disable Telnet service
    - Disable SNMP service if not required
    - Set non-critical services to Manual startup
    - Document all service state changes
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

# Services to disable completely (stopped and startup type disabled)
$ServicesToDisable = @(
    @{ Name = "RemoteRegistry";     DisplayName = "Remote Registry" }
    @{ Name = "Spooler";            DisplayName = "Print Spooler" }
    @{ Name = "TlntSvr";            DisplayName = "Telnet" }
    @{ Name = "SNMP";               DisplayName = "SNMP Service" }
    @{ Name = "XblAuthManager";     DisplayName = "Xbox Live Auth Manager" }
    @{ Name = "XblGameSave";        DisplayName = "Xbox Live Game Save" }
    @{ Name = "XboxGipSvc";         DisplayName = "Xbox Accessory Management Service" }
    @{ Name = "XboxNetApiSvc";      DisplayName = "Xbox Live Networking Service" }
)

# Services to set to Manual startup (not disabled, but won't auto-start)
$ServicesToManual = @(
    @{ Name = "WinRM";              DisplayName = "Windows Remote Management (WS-Management)" }
    @{ Name = "lmhosts";            DisplayName = "TCP/IP NetBIOS Helper" }
    @{ Name = "MapsBroker";         DisplayName = "Downloaded Maps Manager" }
    @{ Name = "WerSvc";             DisplayName = "Windows Error Reporting Service" }
    @{ Name = "DiagTrack";          DisplayName = "Connected User Experiences and Telemetry" }
)

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

function Get-ServiceStatus {
    <#
    .SYNOPSIS
        Gets detailed service status information.
    #>
    param([string]$ServiceName)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return $null
    }
    
    $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    
    return @{
        Name        = $service.Name
        DisplayName = $service.DisplayName
        Status      = $service.Status.ToString()
        StartType   = $wmiService.StartMode
    }
} function Set-ServiceDisabled {
    <#
    .SYNOPSIS
        Stops and disables a service, logging the change.
    #>
    param(
        [string]$ServiceName,
        [string]$DisplayName
    )
    
    $result = @{ Changed = $false; Error = $null }
    
    $before = Get-ServiceStatus -ServiceName $ServiceName
    
    if ($null -eq $before) {
        Write-HardeningLog "Service not found: $DisplayName ($ServiceName)" -Level WARNING
        $result.Error = "Not found"
        return $result
    }
    
    # Log original state
    Write-HardeningLog "Original state: $DisplayName - Status: $($before.Status), StartType: $($before.StartType)" -Level INFO
    
    # Check if already disabled
    if ($before.StartType -eq "Disabled") {
        Write-HardeningLog "Service already disabled: $DisplayName" -Level WARNING
        return $result
    } try {
        # Stop the service if running
        if ($before.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-HardeningLog "Stopped service: $DisplayName" -Level INFO
        }
        
        # Disable the service
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
        
        # Verify the change
        $after = Get-ServiceStatus -ServiceName $ServiceName
        Write-HardeningLog "New state: $DisplayName - Status: $($after.Status), StartType: $($after.StartType)" -Level INFO
        
        $result.Changed = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
} function Set-ServiceManual {
    <#
    .SYNOPSIS
        Sets a service to Manual startup type.
    #>
    param(
        [string]$ServiceName,
        [string]$DisplayName
    )
    
    $result = @{ Changed = $false; Error = $null }
    
    $before = Get-ServiceStatus -ServiceName $ServiceName
    
    if ($null -eq $before) {
        Write-HardeningLog "Service not found: $DisplayName ($ServiceName)" -Level WARNING
        $result.Error = "Not found"
        return $result
    }
    
    # Log original state
    Write-HardeningLog "Original state: $DisplayName - Status: $($before.Status), StartType: $($before.StartType)" -Level INFO
    
    # Check if already Manual or Disabled
    if ($before.StartType -eq "Manual") {
        Write-HardeningLog "Service already set to Manual: $DisplayName" -Level WARNING
        return $result
    } if ($before.StartType -eq "Disabled") {
        Write-HardeningLog "Service is Disabled (more restrictive than Manual): $DisplayName" -Level WARNING
        return $result
    } try {
        # Set to Manual
        Set-Service -Name $ServiceName -StartupType Manual -ErrorAction Stop
        
        # Verify the change
        $after = Get-ServiceStatus -ServiceName $ServiceName
        Write-HardeningLog "New state: $DisplayName - Status: $($after.Status), StartType: $($after.StartType)" -Level INFO
        
        $result.Changed = $true
    } catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# ============================================================================
# ACTION 1: Disable High-Risk Services
# ============================================================================

Write-HardeningLog "Disabling high-risk and unnecessary services" -Level INFO

foreach ($svc in $ServicesToDisable) {
    $attempted++
    Write-HardeningLog "Processing service: $($svc.DisplayName)" -Level INFO
    
    $result = Set-ServiceDisabled -ServiceName $svc.Name -DisplayName $svc.DisplayName
    
    if ($null -ne $result.Error) {
        if ($result.Error -eq "Not found") {
            # Service not installed is not a failure
            $warnings++
            $succeeded++
        } else {
            Write-HardeningLog "Failed to disable $($svc.DisplayName): $($result.Error)" -Level ERROR
            $failed++
        }
    } elseif ($result.Changed) {
        Write-HardeningLog "Successfully disabled: $($svc.DisplayName)" -Level SUCCESS
        $succeeded++
    } else {
        # Already disabled
        $warnings++
        $succeeded++
    }
}

# ============================================================================
# ACTION 2: Set Non-Critical Services to Manual
# ============================================================================

Write-HardeningLog "Setting non-critical services to Manual startup" -Level INFO

foreach ($svc in $ServicesToManual) {
    $attempted++
    Write-HardeningLog "Processing service: $($svc.DisplayName)" -Level INFO
    
    $result = Set-ServiceManual -ServiceName $svc.Name -DisplayName $svc.DisplayName
    
    if ($null -ne $result.Error) {
        if ($result.Error -eq "Not found") {
            $warnings++
            $succeeded++
        } else {
            Write-HardeningLog "Failed to set $($svc.DisplayName) to Manual: $($result.Error)" -Level ERROR
            $failed++
        }
    } elseif ($result.Changed) {
        Write-HardeningLog "Successfully set to Manual: $($svc.DisplayName)" -Level SUCCESS
        $succeeded++
    } else {
        # Already Manual or Disabled
        $warnings++
        $succeeded++
    }
}

# ============================================================================
# ACTION 3: Verify Critical Services Remain Running
# ============================================================================

$attempted++
Write-HardeningLog "Verifying critical services remain operational" -Level INFO

$criticalServices = @(
    "EventLog",      # Windows Event Log
    "Winmgmt",       # Windows Management Instrumentation
    "Schedule",      # Task Scheduler
    "SENS",          # System Event Notification Service
    "RpcSs"          # Remote Procedure Call
)

$criticalOk = $true

foreach ($svcName in $criticalServices) {
    $status = Get-ServiceStatus -ServiceName $svcName
    
    if ($null -eq $status) {
        Write-HardeningLog "Critical service not found: $svcName" -Level ERROR
        $criticalOk = $false
    } elseif ($status.Status -ne "Running") {
        Write-HardeningLog "Critical service not running: $($status.DisplayName) ($svcName)" -Level ERROR
        $criticalOk = $false
    }
}

if ($criticalOk) {
    Write-HardeningLog "All critical services verified running" -Level SUCCESS
    $succeeded++
} else {
    Write-HardeningLog "One or more critical services are not running" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Generate Service Audit Summary
# ============================================================================

$attempted++
Write-HardeningLog "Generating service configuration summary" -Level INFO

try {
    $disabledCount = 0
    $manualCount = 0
    $autoCount = 0
    
    $allServices = Get-WmiObject -Class Win32_Service
    
    foreach ($svc in $allServices) {
        switch ($svc.StartMode) {
            "Disabled" { $disabledCount++ }
            "Manual"   { $manualCount++ }
            "Auto"     { $autoCount++ }
        }
    }
    
    Write-HardeningLog "Service startup type summary: Auto=$autoCount, Manual=$manualCount, Disabled=$disabledCount" -Level INFO
    Write-HardeningLog "Service hardening complete" -Level SUCCESS
    $succeeded++
} catch {
    Write-HardeningLog "Failed to generate service summary: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# RETURN RESULTS
# ============================================================================

return @{
    Success          = ($failed -eq 0)
    ActionsAttempted = $attempted
    ActionsSucceeded = $succeeded
    ActionsWarning   = $warnings
    ActionsFailed    = $failed
}