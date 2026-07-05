<#
.SYNOPSIS
    Master orchestration script for Windows Server security hardening.

.DESCRIPTION
    This script coordinates the execution of nine security hardening modules on a fresh
    Windows Server installation. It provides centralized logging, error handling, and
    execution tracking across all modules.

.NOTES
    Project:      SYS-255 Final Project - Configuring and Securing Windows with Scripting
    Author:       Aaron Ho
    Contributors: Andrew Zombek, Nad AlDulaimi
    Course:       SYS-255-01: Sysadmin and Net Services I
    Professor:    Joseph Letourneau
    Date:         April 2026

.EXAMPLE
    .\Invoke-ServerHardening.ps1
    Runs all hardening modules with default settings.

.EXAMPLE
    .\Invoke-ServerHardening.ps1 -SkipModules 7,8
    Runs all modules except Service Hardening (7) and Attack Surface Reduction (8).
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Module numbers to skip (1-9)")]
    [ValidateRange(1, 9)]
    [int[]]$SkipModules = @(),

    [Parameter(HelpMessage = "Path to output log files")]
    [string]$LogDirectory = "C:\HardeningLogs",

    [Parameter(HelpMessage = "Stop execution if any module fails")]
    [switch]$StopOnFailure
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Config = @{
    Version        = "1.0.0"
    LogDirectory   = $LogDirectory
    LogFile        = $null  # Set during initialization
    StartTime      = $null
    ModulesPath    = $PSScriptRoot
}

$Script:ModuleDefinitions = @(
    @{ Number = 1; Name = "User Account Hardening";           Script = "Module1-UserAccounts.ps1" }
    @{ Number = 2; Name = "Password and Lockout Policy";      Script = "Module2-PasswordPolicy.ps1" }
    @{ Number = 3; Name = "Local Group Membership Audit";     Script = "Module3-GroupAudit.ps1" }
    @{ Number = 4; Name = "Audit Policy and Logging";         Script = "Module4-AuditPolicy.ps1" }
    @{ Number = 5; Name = "File System Permissions";          Script = "Module5-FilePermissions.ps1" }
    @{ Number = 6; Name = "Windows Firewall Configuration";   Script = "Module6-Firewall.ps1" }
    @{ Number = 7; Name = "Service Hardening";                Script = "Module7-Services.ps1" }
    @{ Number = 8; Name = "Attack Surface Reduction";         Script = "Module8-AttackSurface.ps1" }
    @{ Number = 9; Name = "Registry Security Hardening";      Script = "Module9-Registry.ps1" }
)

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Initialize-HardeningLog {
    <#
    .SYNOPSIS
        Initializes the logging system and creates the log file.
    #>

    if (-not (Test-Path -Path $Script:Config.LogDirectory)) {
        New-Item -Path $Script:Config.LogDirectory -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $Script:Config.LogFile = Join-Path -Path $Script:Config.LogDirectory -ChildPath "Hardening_$timestamp.log"
    $Script:Config.StartTime = Get-Date

    # Write log header
    $header = @"
================================================================================
 WINDOWS SERVER SECURITY HARDENING LOG
 Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
 Computer:  $env:COMPUTERNAME
 User:      $env:USERNAME
 Script:    v$($Script:Config.Version)
================================================================================

"@
    $header | Out-File -FilePath $Script:Config.LogFile -Encoding UTF8
}

function global:Write-HardeningLog {
    <#
    .SYNOPSIS
        Writes a timestamped entry to the hardening log and console.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        Log level: INFO, SUCCESS, WARNING, or ERROR.

    .PARAMETER NoConsole
        Suppresses console output (log file only).
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO",

        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to log file
    $logEntry | Out-File -FilePath $Script:Config.LogFile -Append -Encoding UTF8

    # Write to console with color coding
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "INFO"    { "Cyan" }
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
        } Write-Host $logEntry -ForegroundColor $color
    }
}

function global:Write-ModuleHeader {
    <#
    .SYNOPSIS
        Writes a formatted header for a module section in the log.
    #>

    param(
        [Parameter(Mandatory)]
        [int]$ModuleNumber,

        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    $separator = "-" * 70
    $header = @"

$separator
 MODULE $ModuleNumber : $($ModuleName.ToUpper())
$separator
"@

    $header | Out-File -FilePath $Script:Config.LogFile -Append -Encoding UTF8
    Write-Host "`n$separator" -ForegroundColor White
    Write-Host " MODULE $ModuleNumber : $($ModuleName.ToUpper())" -ForegroundColor White
    Write-Host "$separator" -ForegroundColor White
}

# ============================================================================
# MODULE EXECUTION
# ============================================================================

function Invoke-HardeningModule {
    <#
    .SYNOPSIS
        Executes a single hardening module and captures its results.

    .DESCRIPTION
        Modules must return a hashtable with the following structure:
        @{
            Success          = [bool]    # Overall success status
            ActionsAttempted = [int]     # Total actions attempted
            ActionsSucceeded = [int]     # Actions completed successfully
            ActionsWarning   = [int]     # Actions with warnings
            ActionsFailed    = [int]     # Actions that failed
        }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ModuleDefinition
    )

    $moduleNumber = $ModuleDefinition.Number
    $moduleName = $ModuleDefinition.Name
    $moduleScript = $ModuleDefinition.Script
    $modulePath = Join-Path -Path $Script:Config.ModulesPath -ChildPath $moduleScript

    Write-ModuleHeader -ModuleNumber $moduleNumber -ModuleName $moduleName

    # Default result structure for failed execution
    $result = @{
        Success          = $false
        ActionsAttempted = 0
        ActionsSucceeded = 0
        ActionsWarning   = 0
        ActionsFailed    = 0
        ExecutionTime    = [TimeSpan]::Zero
        Error            = $null
    }

    # Check if module script exists
    if (-not (Test-Path -Path $modulePath)) {
        Write-HardeningLog "Module script not found: $moduleScript" -Level ERROR
        $result.Error = "Script file not found"
        return $result
    }

    # Execute the module
    $moduleStart = Get-Date
    Write-HardeningLog "Executing module script: $moduleScript" -Level INFO

    try {
        # Dot-source the module so it can access our logging functions
        $moduleResult = . $modulePath

        # Validate module return value
        if ($moduleResult -is [hashtable]) {
            $result.Success          = [bool]$moduleResult.Success
            $result.ActionsAttempted = [int]$moduleResult.ActionsAttempted
            $result.ActionsSucceeded = [int]$moduleResult.ActionsSucceeded
            $result.ActionsWarning   = [int]$moduleResult.ActionsWarning
            $result.ActionsFailed    = [int]$moduleResult.ActionsFailed
        } else {
            Write-HardeningLog "Module returned unexpected type (expected hashtable)" -Level WARNING
            $result.Success = ($null -ne $moduleResult)
        }
    } catch {
        Write-HardeningLog "Module execution failed: $($_.Exception.Message)" -Level ERROR
        $result.Error = $_.Exception.Message
    }

    $result.ExecutionTime = (Get-Date) - $moduleStart

    # Log module completion
    $status = if ($result.Success) { "SUCCESS" } else { "ERROR" }
    $summary = "Completed: $($result.ActionsSucceeded)/$($result.ActionsAttempted) actions"
    if ($result.ActionsWarning -gt 0) { $summary += ", $($result.ActionsWarning) warnings" }
    if ($result.ActionsFailed -gt 0)  { $summary += ", $($result.ActionsFailed) failed" }
    $summary += " [$($result.ExecutionTime.TotalSeconds.ToString('F1'))s]"

    Write-HardeningLog "Module $moduleNumber complete. $summary" -Level $status

    return $result
}

# ============================================================================
# SUMMARY REPORT
# ============================================================================

function Write-SummaryReport {
    <#
    .SYNOPSIS
        Generates and displays the final execution summary.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Results,

        [Parameter()]
        [int[]]$SkippedModules = @()
    )

    $totalTime = (Get-Date) - $Script:Config.StartTime
    
    # Sum results manually (Measure-Object doesn't work well with hashtable keys)
    $totalAttempted = 0
    $totalSucceeded = 0
    $totalWarnings  = 0
    $totalFailed    = 0
    $modulesSucceeded = 0
    $modulesFailed = 0
    
    foreach ($r in $Results) {
        $totalAttempted += $r.ActionsAttempted
        $totalSucceeded += $r.ActionsSucceeded
        $totalWarnings  += $r.ActionsWarning
        $totalFailed    += $r.ActionsFailed
        if ($r.Success) { $modulesSucceeded++ } else { $modulesFailed++ }
    }

    $separator = "=" * 70

    $report = @"

$separator
 HARDENING SUMMARY REPORT
$separator
 Execution Time:     $($totalTime.TotalSeconds.ToString("F2")) seconds
 Modules Executed:   $($Results.Count) of $($Script:ModuleDefinitions.Count)
 Modules Skipped:    $($SkippedModules.Count)

 MODULE RESULTS
   Succeeded:        $modulesSucceeded
   Failed:           $modulesFailed

 ACTION TOTALS
   Attempted:        $totalAttempted
   Succeeded:        $totalSucceeded
   Warnings:         $totalWarnings
   Failed:           $totalFailed

 Log File:           $($Script:Config.LogFile)
$separator
"@

    # Write to log file
    $report | Out-File -FilePath $Script:Config.LogFile -Append -Encoding UTF8

    # Write to console with color
    Write-Host "`n$separator" -ForegroundColor White
    Write-Host " HARDENING SUMMARY REPORT" -ForegroundColor White
    Write-Host $separator -ForegroundColor White
    Write-Host " Execution Time:     $($totalTime.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Cyan
    Write-Host " Modules Executed:   $($Results.Count) of $($Script:ModuleDefinitions.Count)" -ForegroundColor Cyan
    Write-Host " Modules Skipped:    $($SkippedModules.Count)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " MODULE RESULTS" -ForegroundColor White
    Write-Host "   Succeeded:        $modulesSucceeded" -ForegroundColor Green
    Write-Host "   Failed:           $modulesFailed" -ForegroundColor $(if ($modulesFailed -gt 0) { "Red" } else { "Green" })
    Write-Host ""
    Write-Host " ACTION TOTALS" -ForegroundColor White
    Write-Host "   Attempted:        $totalAttempted" -ForegroundColor Cyan
    Write-Host "   Succeeded:        $totalSucceeded" -ForegroundColor Green
    Write-Host "   Warnings:         $totalWarnings" -ForegroundColor $(if ($totalWarnings -gt 0) { "Yellow" } else { "Cyan" })
    Write-Host "   Failed:           $totalFailed" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Cyan" })
    Write-Host ""
    Write-Host " Log File:           $($Script:Config.LogFile)" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor White

    # Return overall success status
    return ($modulesFailed -eq 0 -and $totalFailed -eq 0)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    # Initialize logging
    Initialize-HardeningLog

    Write-HardeningLog "Windows Server Security Hardening Script v$($Script:Config.Version)" -Level INFO
    Write-HardeningLog "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level INFO

    # Log skipped modules if any
    if ($SkipModules.Count -gt 0) {
        $skippedNames = ($Script:ModuleDefinitions | Where-Object { $_.Number -in $SkipModules }).Name -join ", "
        Write-HardeningLog "Modules marked to skip: $skippedNames" -Level INFO
    }

    # Execute modules
    $results = @()

    foreach ($module in $Script:ModuleDefinitions) {
        if ($module.Number -in $SkipModules) {
            Write-HardeningLog "Skipping Module $($module.Number): $($module.Name)" -Level INFO
            continue
        }

        $result = Invoke-HardeningModule -ModuleDefinition $module
        $results += $result

        # Check for stop on failure
        if ($StopOnFailure -and -not $result.Success) {
            Write-HardeningLog "StopOnFailure enabled. Halting execution." -Level ERROR
            break
        }
    }

    # Generate summary report
    $overallSuccess = Write-SummaryReport -Results $results -SkippedModules $SkipModules

    Write-HardeningLog "Hardening script execution complete." -Level INFO

    # Exit with appropriate code
    if ($overallSuccess) {
        exit 0
    } else {
        exit 1
    }
}

# Run main function
Main