#Requires -Version 5.1
<#
.SYNOPSIS
    Module de scheduling des métriques pour DEX Collector.

.DESCRIPTION
    Gère la planification et l'ordonnancement des collectes de métriques
    selon leurs fréquences configurées. Supporte le groupement par fréquence
    et les métriques event-driven.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

# Variables de module
$script:ScheduledMetrics = @{}
$script:FrequencyGroups = @{}
$script:LastCollectionTimes = @{}
$script:IsRunning = $false

function Initialize-Scheduler {
    <#
    .SYNOPSIS
        Initialise le scheduler avec la configuration des métriques.

    .PARAMETER MetricsConfig
        Configuration des métriques (résultat de Get-MetricsConfiguration).

    .OUTPUTS
        Booléen indiquant le succès de l'initialisation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig
    )

    try {
        # Reset
        $script:ScheduledMetrics = @{}
        $script:FrequencyGroups = @{}
        $script:LastCollectionTimes = @{}

        # Filtrer les métriques activées
        $enabledMetrics = $MetricsConfig.Metrics.Values | Where-Object { $_.Enabled }

        foreach ($metric in $enabledMetrics) {
            # Enregistrer la métrique
            $script:ScheduledMetrics[$metric.Name] = $metric

            # Initialiser le timestamp de dernière collecte
            $script:LastCollectionTimes[$metric.Name] = [DateTime]::MinValue

            # Grouper par fréquence (sauf event-driven)
            if (-not $metric.IsEventDriven) {
                $frequency = $metric.FrequencyMinutes

                if (-not $script:FrequencyGroups.ContainsKey($frequency)) {
                    $script:FrequencyGroups[$frequency] = @()
                }

                $script:FrequencyGroups[$frequency] += $metric.Name
            }
        }

        Write-Verbose "Scheduler initialisé avec $($script:ScheduledMetrics.Count) métriques"
        Write-Verbose "Groupes de fréquence: $($script:FrequencyGroups.Keys -join ', ') minutes"

        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation du scheduler: $_"
        return $false
    }
}

function Get-MetricsDueForCollection {
    <#
    .SYNOPSIS
        Retourne les métriques qui doivent être collectées maintenant.

    .PARAMETER CurrentTime
        Timestamp actuel (optionnel, utilise Get-Date par défaut).

    .OUTPUTS
        Array des noms de métriques à collecter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [DateTime]$CurrentTime = (Get-Date)
    )

    $dueMetrics = @()

    foreach ($metricName in $script:ScheduledMetrics.Keys) {
        $metric = $script:ScheduledMetrics[$metricName]

        # Ignorer les métriques event-driven
        if ($metric.IsEventDriven) {
            continue
        }

        $lastCollected = $script:LastCollectionTimes[$metricName]

        # Vérifier si la métrique doit être collectée
        if ($lastCollected -eq [DateTime]::MinValue) {
            # Jamais collectée, collecter maintenant
            $dueMetrics += $metricName
        }
        else {
            $nextCollectionTime = $lastCollected.AddMinutes($metric.FrequencyMinutes)

            if ($CurrentTime -ge $nextCollectionTime) {
                $dueMetrics += $metricName
            }
        }
    }

    return $dueMetrics
}

function Update-MetricLastCollected {
    <#
    .SYNOPSIS
        Met à jour le timestamp de dernière collecte d'une métrique.

    .PARAMETER MetricName
        Nom de la métrique.

    .PARAMETER Timestamp
        Timestamp de la collecte (optionnel, utilise Get-Date par défaut).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName,

        [Parameter(Mandatory = $false)]
        [DateTime]$Timestamp = (Get-Date)
    )

    if ($script:LastCollectionTimes.ContainsKey($MetricName)) {
        $script:LastCollectionTimes[$MetricName] = $Timestamp
    }
}

function Get-SchedulerStatus {
    <#
    .SYNOPSIS
        Retourne l'état actuel du scheduler.

    .OUTPUTS
        PSCustomObject avec les informations de statut.
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date

    $metricStatus = @()

    foreach ($metricName in $script:ScheduledMetrics.Keys) {
        $metric = $script:ScheduledMetrics[$metricName]
        $lastCollected = $script:LastCollectionTimes[$metricName]

        $nextCollection = if ($metric.IsEventDriven) {
            'Event-Driven'
        }
        elseif ($lastCollected -eq [DateTime]::MinValue) {
            'Immediate'
        }
        else {
            $lastCollected.AddMinutes($metric.FrequencyMinutes).ToString('HH:mm:ss')
        }

        $metricStatus += [PSCustomObject]@{
            Name = $metricName
            Category = $metric.Category
            Frequency = if ($metric.IsEventDriven) { 'Event' } else { "$($metric.FrequencyMinutes) min" }
            Priority = $metric.Priority
            LastCollected = if ($lastCollected -eq [DateTime]::MinValue) { 'Never' } else { $lastCollected.ToString('HH:mm:ss') }
            NextCollection = $nextCollection
        }
    }

    return [PSCustomObject]@{
        TotalMetrics = $script:ScheduledMetrics.Count
        FrequencyGroups = $script:FrequencyGroups.Count
        IsRunning = $script:IsRunning
        Metrics = $metricStatus
    }
}

function Get-FrequencyGroups {
    <#
    .SYNOPSIS
        Retourne les groupes de métriques par fréquence.

    .OUTPUTS
        Hashtable avec les fréquences et leurs métriques.
    #>
    [CmdletBinding()]
    param()

    return $script:FrequencyGroups.Clone()
}

function Get-NextCollectionTime {
    <#
    .SYNOPSIS
        Calcule le prochain moment où une collecte doit être effectuée.

    .OUTPUTS
        DateTime du prochain tick de collecte.
    #>
    [CmdletBinding()]
    param()

    $now = Get-Date
    $nextTime = $null

    foreach ($metricName in $script:ScheduledMetrics.Keys) {
        $metric = $script:ScheduledMetrics[$metricName]

        # Ignorer les métriques event-driven
        if ($metric.IsEventDriven) {
            continue
        }

        $lastCollected = $script:LastCollectionTimes[$metricName]

        $nextMetricTime = if ($lastCollected -eq [DateTime]::MinValue) {
            $now
        }
        else {
            $lastCollected.AddMinutes($metric.FrequencyMinutes)
        }

        if ($null -eq $nextTime -or $nextMetricTime -lt $nextTime) {
            $nextTime = $nextMetricTime
        }
    }

    return $nextTime
}

function Get-SleepDuration {
    <#
    .SYNOPSIS
        Calcule la durée de sommeil avant la prochaine collecte.

    .PARAMETER MaxSleepSeconds
        Durée maximum de sommeil en secondes (défaut: 60).

    .OUTPUTS
        Durée en secondes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxSleepSeconds = 60
    )

    $nextTime = Get-NextCollectionTime
    $now = Get-Date

    if ($null -eq $nextTime -or $nextTime -le $now) {
        return 0
    }

    $sleepSeconds = [math]::Floor(($nextTime - $now).TotalSeconds)

    # Limiter au maximum
    return [math]::Min($sleepSeconds, $MaxSleepSeconds)
}

function Get-MetricsByCategory {
    <#
    .SYNOPSIS
        Retourne les métriques groupées par catégorie.

    .OUTPUTS
        Hashtable avec les catégories et leurs métriques.
    #>
    [CmdletBinding()]
    param()

    $byCategory = @{}

    foreach ($metricName in $script:ScheduledMetrics.Keys) {
        $metric = $script:ScheduledMetrics[$metricName]
        $category = $metric.Category

        if (-not $byCategory.ContainsKey($category)) {
            $byCategory[$category] = @()
        }

        $byCategory[$category] += $metric
    }

    return $byCategory
}

function Get-MetricsByPriority {
    <#
    .SYNOPSIS
        Retourne les métriques triées par priorité.

    .OUTPUTS
        Array de métriques triées (high, medium, low).
    #>
    [CmdletBinding()]
    param()

    $priorityOrder = @{
        'high' = 1
        'medium' = 2
        'low' = 3
    }

    $sorted = $script:ScheduledMetrics.Values |
        Sort-Object @{Expression = { $priorityOrder[$_.Priority] }}

    return $sorted
}

function Set-SchedulerRunning {
    <#
    .SYNOPSIS
        Définit l'état du scheduler (en cours ou arrêté).

    .PARAMETER Running
        État du scheduler.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Running
    )

    $script:IsRunning = $Running
}

function Reset-MetricSchedule {
    <#
    .SYNOPSIS
        Réinitialise le planning d'une métrique spécifique.

    .PARAMETER MetricName
        Nom de la métrique à réinitialiser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName
    )

    if ($script:LastCollectionTimes.ContainsKey($MetricName)) {
        $script:LastCollectionTimes[$MetricName] = [DateTime]::MinValue
        Write-Verbose "Planning de '$MetricName' réinitialisé."
    }
}

function Reset-AllSchedules {
    <#
    .SYNOPSIS
        Réinitialise le planning de toutes les métriques.
    #>
    [CmdletBinding()]
    param()

    foreach ($metricName in $script:LastCollectionTimes.Keys) {
        $script:LastCollectionTimes[$metricName] = [DateTime]::MinValue
    }

    Write-Verbose "Tous les plannings ont été réinitialisés."
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Initialize-Scheduler',
    'Get-MetricsDueForCollection',
    'Update-MetricLastCollected',
    'Get-SchedulerStatus',
    'Get-FrequencyGroups',
    'Get-NextCollectionTime',
    'Get-SleepDuration',
    'Get-MetricsByCategory',
    'Get-MetricsByPriority',
    'Set-SchedulerRunning',
    'Reset-MetricSchedule',
    'Reset-AllSchedules'
)
