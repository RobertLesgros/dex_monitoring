#Requires -Version 5.1
<#
.SYNOPSIS
    Script de test pour les collecteurs DEX.

.DESCRIPTION
    Teste chaque collecteur individuellement et affiche les résultats.
    Utile pour valider le bon fonctionnement des métriques.

.EXAMPLE
    .\Test-Collectors.ps1
    Teste tous les collecteurs.

.EXAMPLE
    .\Test-Collectors.ps1 -Collector System
    Teste uniquement le collecteur système.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'System', 'Network', 'Security')]
    [string]$Collector = 'All'
)

# Chemins
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ClientPath = Split-Path -Parent $ScriptPath
$CollectorsPath = Join-Path $ClientPath 'collectors'

# Importer les collecteurs
$systemMetrics = Join-Path $CollectorsPath 'SystemMetrics.psm1'
$networkMetrics = Join-Path $CollectorsPath 'NetworkMetrics.psm1'
$securityMetrics = Join-Path $CollectorsPath 'SecurityMetrics.psm1'

if (Test-Path $systemMetrics) { Import-Module $systemMetrics -Force }
if (Test-Path $networkMetrics) { Import-Module $networkMetrics -Force }
if (Test-Path $securityMetrics) { Import-Module $securityMetrics -Force }

function Test-Metric {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )

    Write-Host "Testing: $Name..." -ForegroundColor Yellow -NoNewline

    try {
        $startTime = Get-Date
        $result = & $ScriptBlock
        $duration = (Get-Date) - $startTime

        if ($result.Success) {
            Write-Host " OK" -ForegroundColor Green -NoNewline
            Write-Host " ($([math]::Round($duration.TotalMilliseconds))ms)" -ForegroundColor Gray
            return $true
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "  Error: $($result.Error)" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host " ERROR" -ForegroundColor Red
        Write-Host "  Exception: $_" -ForegroundColor Red
        return $false
    }
}

function Show-MetricResult {
    param(
        [PSCustomObject]$Result
    )

    if ($Result.Success -and $Result.Data) {
        Write-Host "  Data:" -ForegroundColor Cyan
        $Result.Data.GetEnumerator() | ForEach-Object {
            $value = if ($_.Value -is [hashtable] -or $_.Value -is [array]) {
                ($_.Value | ConvertTo-Json -Compress)
            } else {
                $_.Value
            }
            Write-Host "    $($_.Key): $value" -ForegroundColor Gray
        }
    }
}

# Header
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DEX Collector - Tests des Collecteurs" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$results = @{
    Passed = 0
    Failed = 0
}

# Tests System
if ($Collector -in @('All', 'System')) {
    Write-Host "[System Metrics]" -ForegroundColor Magenta

    if (Test-Metric -Name "CPUUsage" -ScriptBlock { Get-CPUUsage }) { $results.Passed++ } else { $results.Failed++ }
    $cpuResult = Get-CPUUsage
    Show-MetricResult -Result $cpuResult

    if (Test-Metric -Name "MemoryUsage" -ScriptBlock { Get-MemoryUsage }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "DiskSpace" -ScriptBlock { Get-DiskSpace }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "SystemUptime" -ScriptBlock { Get-SystemUptime }) { $results.Passed++ } else { $results.Failed++ }

    Write-Host ""
}

# Tests Network
if ($Collector -in @('All', 'Network')) {
    Write-Host "[Network Metrics]" -ForegroundColor Magenta

    if (Test-Metric -Name "InternetConnectivity" -ScriptBlock { Get-InternetConnectivity }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "GatewayLatency" -ScriptBlock { Get-GatewayLatency }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "DNSResolution" -ScriptBlock { Get-DNSResolution }) { $results.Passed++ } else { $results.Failed++ }

    Write-Host ""
}

# Tests Security
if ($Collector -in @('All', 'Security')) {
    Write-Host "[Security Metrics]" -ForegroundColor Magenta

    if (Test-Metric -Name "AntivirusStatus" -ScriptBlock { Get-AntivirusStatus }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "FirewallStatus" -ScriptBlock { Get-FirewallStatus }) { $results.Passed++ } else { $results.Failed++ }
    if (Test-Metric -Name "WindowsUpdateStatus" -ScriptBlock { Get-WindowsUpdateStatus }) { $results.Passed++ } else { $results.Failed++ }

    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Résultats" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Passed: $($results.Passed)" -ForegroundColor Green
Write-Host "  Failed: $($results.Failed)" -ForegroundColor $(if ($results.Failed -gt 0) { 'Red' } else { 'Gray' })
Write-Host ""

if ($results.Failed -eq 0) {
    Write-Host "Tous les tests ont réussi!" -ForegroundColor Green
}
else {
    Write-Host "Certains tests ont échoué." -ForegroundColor Yellow
}
