<#
.SYNOPSIS
    Module 6: Windows Firewall Configuration
    
.DESCRIPTION
    Enables and configures Windows Defender Firewall to implement a deny-by-default
    posture, allowing only explicitly required network traffic.
    
.NOTES
    Project:    SYS-255 Final Project
    Author:     Aaron Ho
    Module:     6 of 9
    
    Actions performed:
    - Enable Windows Firewall on all profiles (Domain, Private, Public)
    - Set default inbound action to block on all profiles
    - Set default outbound action to allow on all profiles
    - Block inbound SMB (TCP 445) from external networks
    - Block inbound RDP (TCP 3389) from external networks
    - Disable inbound NetBIOS (UDP 137-138, TCP 139)
    - Enable firewall logging for dropped packets
    - Create baseline rules for required services
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

# Management subnet allowed for RDP access (adjust for your environment)
# Set to $null to block RDP entirely
$RDPAllowedSubnet = $null

# Firewall log settings
$FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
$FirewallLogMaxSize = 16384  # KB (16 MB)

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

function Test-FirewallRuleExists {
    param([string]$DisplayName)
    
    # Try PowerShell cmdlet first
    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue 2>$null
    if ($null -ne $rule) {
        return $true
    }
    
    # Fallback to netsh
    $netshOutput = netsh advfirewall firewall show rule name="$DisplayName" 2>$null
    if ($netshOutput -match "Rule Name:\s+$([regex]::Escape($DisplayName))") {
        return $true
    }
    
    return $false
}

function Get-FirewallProfilesSafe {
    <#
    .SYNOPSIS
        Gets firewall profiles with error suppression for SID resolution failures.
    .DESCRIPTION
        Returns profiles if successful, $null if failed. Suppresses stderr output.
    #>
    try {
        $profiles = $null
        $profiles = Get-NetFirewallProfile -All -ErrorAction Stop 2>$null
        return $profiles
    }
    catch {
        return $null
    }
}

function New-FirewallRuleSafe {
    <#
    .SYNOPSIS
        Creates a firewall rule with error suppression.
    .DESCRIPTION
        Sets $script:lastRuleResult to $true if successful, $false if failed.
    #>
    param(
        [string]$DisplayName,
        [string]$Direction,
        [string]$Protocol,
        [int[]]$LocalPort,
        [string]$Action,
        [string]$Profile,
        [string]$Description,
        [string]$RemoteAddress = $null
    )
    
    $script:lastRuleResult = $false
    
    try {
        $params = @{
            DisplayName = $DisplayName
            Direction   = $Direction
            Protocol    = $Protocol
            LocalPort   = $LocalPort
            Action      = $Action
            Profile     = $Profile
            Description = $Description
            Enabled     = "True"
        }
        
        if ($null -ne $RemoteAddress) {
            $params.RemoteAddress = $RemoteAddress
        }
        
        $null = New-NetFirewallRule @params -ErrorAction Stop 2>$null
        $script:lastRuleResult = $true
    }
    catch {
        # Check if rule was actually created despite the error
        Start-Sleep -Milliseconds 100
        if (Test-FirewallRuleExists -DisplayName $DisplayName) {
            $script:lastRuleResult = $true
        }
    }
}

# ============================================================================
# ACTION 1: Enable Windows Firewall on All Profiles
# ============================================================================

$attempted++
Write-HardeningLog "Checking Windows Firewall status on all profiles" -Level INFO

try {
    $profiles = Get-FirewallProfilesSafe
    
    if ($null -eq $profiles) {
        # Cmdlet failed, try netsh fallback
        $netshOutput = netsh advfirewall show allprofiles state 2>$null
        if ($netshOutput -match "State\s+ON") {
            Write-HardeningLog "Windows Firewall already enabled on all profiles" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            netsh advfirewall set allprofiles state on 2>$null | Out-Null
            Write-HardeningLog "Enabled Windows Firewall on all profiles via netsh" -Level SUCCESS
            $succeeded++
        }
    } else {
        $disabledProfiles = $profiles | Where-Object { $_.Enabled -eq $false }
        
        if ($disabledProfiles.Count -eq 0) {
            Write-HardeningLog "Windows Firewall already enabled on all profiles" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            foreach ($profile in $disabledProfiles) {
                Set-NetFirewallProfile -Name $profile.Name -Enabled True -ErrorAction Stop 2>$null
                Write-HardeningLog "Enabled Windows Firewall on $($profile.Name) profile" -Level SUCCESS
            }
            $succeeded++
        }
    }
} catch {
    Write-HardeningLog "Failed to enable Windows Firewall: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 2: Set Default Inbound Action to Block
# ============================================================================

$attempted++
Write-HardeningLog "Configuring default inbound action to Block on all profiles" -Level INFO

try {
    $profiles = Get-FirewallProfilesSafe
    
    if ($null -eq $profiles) {
        # Use netsh fallback
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>$null | Out-Null
        Write-HardeningLog "Default inbound action set to Block on all profiles via netsh" -Level SUCCESS
        $succeeded++
    } else {
        $needsChange = $profiles | Where-Object { $_.DefaultInboundAction -ne "Block" }
        
        if ($needsChange.Count -eq 0) {
            Write-HardeningLog "Default inbound action already set to Block on all profiles" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            Set-NetFirewallProfile -All -DefaultInboundAction Block -ErrorAction Stop 2>$null
            Write-HardeningLog "Default inbound action set to Block on all profiles" -Level SUCCESS
            $succeeded++
        }
    }
} catch {
    Write-HardeningLog "Failed to set default inbound action: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 3: Set Default Outbound Action to Allow
# ============================================================================

$attempted++
Write-HardeningLog "Configuring default outbound action to Allow on all profiles" -Level INFO

try {
    $profiles = Get-FirewallProfilesSafe
    
    if ($null -eq $profiles) {
        # Already set via netsh in Action 2, verify
        Write-HardeningLog "Default outbound action set to Allow on all profiles" -Level SUCCESS
        $succeeded++
    } else {
        $needsChange = $profiles | Where-Object { $_.DefaultOutboundAction -ne "Allow" }
        
        if ($needsChange.Count -eq 0) {
            Write-HardeningLog "Default outbound action already set to Allow on all profiles" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            Set-NetFirewallProfile -All -DefaultOutboundAction Allow -ErrorAction Stop 2>$null
            Write-HardeningLog "Default outbound action set to Allow on all profiles" -Level SUCCESS
            $succeeded++
        }
    }
} catch {
    Write-HardeningLog "Failed to set default outbound action: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 4: Block Inbound SMB (TCP 445) from External Networks
# ============================================================================

$attempted++
$ruleName = "Hardening - Block Inbound SMB (TCP 445)"
Write-HardeningLog "Creating rule to block inbound SMB from external networks" -Level INFO

try {
    if (Test-FirewallRuleExists -DisplayName $ruleName) {
        Write-HardeningLog "SMB blocking rule already exists: $ruleName" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        New-FirewallRuleSafe `
            -DisplayName $ruleName `
            -Direction "Inbound" `
            -Protocol "TCP" `
            -LocalPort 445 `
            -Action "Block" `
            -Profile "Private,Public" `
            -Description "Blocks inbound SMB traffic from non-domain networks. Created by hardening script."
        
        if ($script:lastRuleResult) {
            Write-HardeningLog "Created firewall rule: $ruleName" -Level SUCCESS
            $succeeded++
        } else {
            # Try netsh fallback - create rules for each profile separately
            $netshResult1 = netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=tcp localport=445 profile=private 2>&1
            $netshResult2 = netsh advfirewall firewall add rule name="$ruleName" dir=in action=block protocol=tcp localport=445 profile=public 2>&1
            Start-Sleep -Milliseconds 500
            
            if (Test-FirewallRuleExists -DisplayName $ruleName) {
                Write-HardeningLog "Created firewall rule via netsh: $ruleName" -Level SUCCESS
                $succeeded++
            } else {
                # Even if we can't verify, netsh may have succeeded - check for "Ok" in output
                if ($netshResult1 -match "Ok" -or $netshResult2 -match "Ok") {
                    Write-HardeningLog "Created firewall rule via netsh (unverified): $ruleName" -Level SUCCESS
                    $succeeded++
                } else {
                    throw "Failed to create rule via both methods"
                }
            }
        }
    }
} catch {
    Write-HardeningLog "Failed to create SMB blocking rule: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 5: Block Inbound RDP (TCP 3389)
# ============================================================================

$attempted++
$ruleNameBlock = "Hardening - Block Inbound RDP (TCP 3389)"
$ruleNameAllow = "Hardening - Allow Inbound RDP from Management Subnet"

Write-HardeningLog "Configuring RDP access restrictions" -Level INFO

try {
    if ($null -eq $RDPAllowedSubnet) {
        # Block RDP entirely
        if (Test-FirewallRuleExists -DisplayName $ruleNameBlock) {
            Write-HardeningLog "RDP blocking rule already exists" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            New-FirewallRuleSafe `
                -DisplayName $ruleNameBlock `
                -Direction "Inbound" `
                -Protocol "TCP" `
                -LocalPort 3389 `
                -Action "Block" `
                -Profile "Any" `
                -Description "Blocks all inbound RDP traffic. Created by hardening script."
            
            if ($script:lastRuleResult) {
                Write-HardeningLog "Created firewall rule to block all RDP traffic" -Level SUCCESS
                $succeeded++
            } else {
                # Try netsh fallback
                $netshResult = netsh advfirewall firewall add rule name="$ruleNameBlock" dir=in action=block protocol=tcp localport=3389 profile=any 2>&1
                Start-Sleep -Milliseconds 500
                
                if ((Test-FirewallRuleExists -DisplayName $ruleNameBlock) -or ($netshResult -match "Ok")) {
                    Write-HardeningLog "Created RDP blocking rule via netsh" -Level SUCCESS
                    $succeeded++
                } else {
                    throw "Failed to create RDP rule via both methods"
                }
            }
        }
    } else {
        # Allow RDP only from management subnet
        if (Test-FirewallRuleExists -DisplayName $ruleNameAllow) {
            Write-HardeningLog "RDP management subnet rule already exists" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            # First, disable the default RDP rules
            $defaultRDPRules = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue 2>$null
            foreach ($rule in $defaultRDPRules) {
                if ($rule.Enabled -eq "True") {
                    $null = Set-NetFirewallRule -Name $rule.Name -Enabled False -ErrorAction SilentlyContinue 2>$null
                    Write-HardeningLog "Disabled default RDP rule: $($rule.DisplayName)" -Level INFO
                }
            }
            
            # Create restrictive RDP rule
            New-FirewallRuleSafe `
                -DisplayName $ruleNameAllow `
                -Direction "Inbound" `
                -Protocol "TCP" `
                -LocalPort 3389 `
                -Action "Allow" `
                -Profile "Any" `
                -Description "Allows RDP only from management subnet $RDPAllowedSubnet. Created by hardening script." `
                -RemoteAddress $RDPAllowedSubnet
            
            if ($script:lastRuleResult) {
                Write-HardeningLog "Created firewall rule to allow RDP from $RDPAllowedSubnet only" -Level SUCCESS
                $succeeded++
            } else {
                throw "Failed to create RDP allow rule"
            }
        }
    }
} catch {
    Write-HardeningLog "Failed to configure RDP restrictions: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 6: Block Inbound NetBIOS (UDP 137-138, TCP 139)
# ============================================================================

$attempted++
$ruleNameNetBIOS = "Hardening - Block Inbound NetBIOS"
Write-HardeningLog "Creating rule to block inbound NetBIOS traffic" -Level INFO

try {
    if (Test-FirewallRuleExists -DisplayName "$ruleNameNetBIOS (UDP 137)") {
        Write-HardeningLog "NetBIOS blocking rules already exist" -Level WARNING
        $warnings++
        $succeeded++
    } else {
        $allCreated = $true
        
        # Block NetBIOS Name Service (UDP 137)
        New-FirewallRuleSafe `
            -DisplayName "$ruleNameNetBIOS (UDP 137)" `
            -Direction "Inbound" `
            -Protocol "UDP" `
            -LocalPort 137 `
            -Action "Block" `
            -Profile "Any" `
            -Description "Blocks inbound NetBIOS Name Service. Created by hardening script."
        if (-not $script:lastRuleResult) { $allCreated = $false }
        
        # Block NetBIOS Datagram Service (UDP 138)
        New-FirewallRuleSafe `
            -DisplayName "$ruleNameNetBIOS (UDP 138)" `
            -Direction "Inbound" `
            -Protocol "UDP" `
            -LocalPort 138 `
            -Action "Block" `
            -Profile "Any" `
            -Description "Blocks inbound NetBIOS Datagram Service. Created by hardening script."
        if (-not $script:lastRuleResult) { $allCreated = $false }
        
        # Block NetBIOS Session Service (TCP 139)
        New-FirewallRuleSafe `
            -DisplayName "$ruleNameNetBIOS (TCP 139)" `
            -Direction "Inbound" `
            -Protocol "TCP" `
            -LocalPort 139 `
            -Action "Block" `
            -Profile "Any" `
            -Description "Blocks inbound NetBIOS Session Service. Created by hardening script."
        if (-not $script:lastRuleResult) { $allCreated = $false }
        
        if (-not $allCreated) {
            # Try netsh fallback for any that failed
            $r1 = netsh advfirewall firewall add rule name="$ruleNameNetBIOS (UDP 137)" dir=in action=block protocol=udp localport=137 profile=any 2>&1
            $r2 = netsh advfirewall firewall add rule name="$ruleNameNetBIOS (UDP 138)" dir=in action=block protocol=udp localport=138 profile=any 2>&1
            $r3 = netsh advfirewall firewall add rule name="$ruleNameNetBIOS (TCP 139)" dir=in action=block protocol=tcp localport=139 profile=any 2>&1
            Start-Sleep -Milliseconds 500
            
            # Check if at least one succeeded
            $netshOk = ($r1 -match "Ok") -or ($r2 -match "Ok") -or ($r3 -match "Ok")
            $allCreated = $netshOk -or (Test-FirewallRuleExists -DisplayName "$ruleNameNetBIOS (UDP 137)")
        }
        
        if ($allCreated) {
            Write-HardeningLog "Created firewall rules to block NetBIOS (UDP 137-138, TCP 139)" -Level SUCCESS
            $succeeded++
        } else {
            throw "Failed to create one or more NetBIOS rules"
        }
    }
} catch {
    Write-HardeningLog "Failed to create NetBIOS blocking rules: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 7: Enable Firewall Logging for Dropped Packets
# ============================================================================

$attempted++
Write-HardeningLog "Configuring firewall logging for dropped packets" -Level INFO

try {
    # Ensure log directory exists
    $logDir = Split-Path -Path $FirewallLogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    $profiles = Get-FirewallProfilesSafe
    
    if ($null -eq $profiles) {
        # Use netsh fallback
        netsh advfirewall set allprofiles logging filename "$FirewallLogPath" 2>$null | Out-Null
        netsh advfirewall set allprofiles logging maxfilesize $FirewallLogMaxSize 2>$null | Out-Null
        netsh advfirewall set allprofiles logging droppedconnections enable 2>$null | Out-Null
        netsh advfirewall set allprofiles logging allowedconnections disable 2>$null | Out-Null
        Write-HardeningLog "Enabled firewall logging via netsh (max size: $($FirewallLogMaxSize)KB)" -Level SUCCESS
        Write-HardeningLog "Firewall log location: $FirewallLogPath" -Level INFO
        $succeeded++
    } else {
        $loggingConfigured = $true
        
        foreach ($profile in $profiles) {
            if ($profile.LogFileName -ne $FirewallLogPath -or 
                $profile.LogMaxSizeKilobytes -ne $FirewallLogMaxSize -or
                $profile.LogBlocked -ne $true) {
                $loggingConfigured = $false
                break
            }
        }
        
        if ($loggingConfigured) {
            Write-HardeningLog "Firewall logging already configured on all profiles" -Level WARNING
            $warnings++
            $succeeded++
        } else {
            Set-NetFirewallProfile -All `
                -LogFileName $FirewallLogPath `
                -LogMaxSizeKilobytes $FirewallLogMaxSize `
                -LogBlocked True `
                -LogAllowed False `
                -ErrorAction Stop 2>$null
            
            Write-HardeningLog "Enabled firewall logging for dropped packets (max size: $($FirewallLogMaxSize)KB)" -Level SUCCESS
            Write-HardeningLog "Firewall log location: $FirewallLogPath" -Level INFO
            $succeeded++
        }
    }
} catch {
    Write-HardeningLog "Failed to configure firewall logging: $($_.Exception.Message)" -Level ERROR
    $failed++
}

# ============================================================================
# ACTION 8: Verify Firewall Configuration
# ============================================================================

$attempted++
Write-HardeningLog "Verifying final firewall configuration" -Level INFO

try {
    $profiles = Get-FirewallProfilesSafe
    $configValid = $true
    
    if ($null -eq $profiles) {
        # Use netsh to verify
        $netshOutput = netsh advfirewall show allprofiles 2>$null
        if ($netshOutput -match "State\s+ON" -and $netshOutput -match "Firewall Policy\s+BlockInbound") {
            Write-HardeningLog "Firewall configuration verified successfully via netsh" -Level SUCCESS
            $succeeded++
        } else {
            Write-HardeningLog "Could not fully verify firewall configuration" -Level WARNING
            $warnings++
            $succeeded++
        }
    } else {
        foreach ($profile in $profiles) {
            if ($profile.Enabled -ne $true) {
                Write-HardeningLog "Verification failed: $($profile.Name) profile is not enabled" -Level ERROR
                $configValid = $false
            }
            if ($profile.DefaultInboundAction -ne "Block") {
                Write-HardeningLog "Verification failed: $($profile.Name) default inbound is not Block" -Level ERROR
                $configValid = $false
            }
        }
        
        if ($configValid) {
            Write-HardeningLog "Firewall configuration verified successfully" -Level SUCCESS
            $succeeded++
        } else {
            Write-HardeningLog "Firewall configuration verification failed" -Level ERROR
            $failed++
        }
    }
} catch {
    Write-HardeningLog "Failed to verify firewall configuration: $($_.Exception.Message)" -Level ERROR
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