#Requires -Version 5.1
<#
.SYNOPSIS
    Module d'orchestration de la collecte de métriques pour DEX Collector.

.DESCRIPTION
    Orchestre la collecte des métriques en invoquant les collecteurs spécialisés
    appropriés et en assemblant les résultats en JSON structuré.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

# Import des collecteurs (à faire depuis le script principal)
# Ces variables stockent les chemins des modules
$script:CollectorsPath = $null
$script:CollectorVersion = '1.0.0'
$script:SystemInfo = $null

function Initialize-MetricsCollector {
    <#
    .SYNOPSIS
        Initialise le collecteur de métriques.

    .PARAMETER CollectorsPath
        Chemin vers le dossier des collecteurs.

    .PARAMETER CollectorVersion
        Version du collecteur.

    .OUTPUTS
        Booléen indiquant le succès de l'initialisation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectorsPath,

        [Parameter(Mandatory = $false)]
        [string]$CollectorVersion = '1.0.0'
    )

    try {
        $script:CollectorsPath = $CollectorsPath
        $script:CollectorVersion = $CollectorVersion

        # Vérifier que les collecteurs existent
        $requiredCollectors = @(
            'SystemMetrics.psm1',
            'NetworkMetrics.psm1',
            'SecurityMetrics.psm1'
        )

        foreach ($collector in $requiredCollectors) {
            $collectorPath = Join-Path $CollectorsPath $collector
            if (-not (Test-Path $collectorPath)) {
                Write-Warning "Collecteur manquant: $collector"
            }
        }

        # Collecter les informations système de base (cache)
        $script:SystemInfo = Get-BaseSystemInfo

        Write-Verbose "MetricsCollector initialisé. Version: $CollectorVersion"
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation du MetricsCollector: $_"
        return $false
    }
}

function Get-BaseSystemInfo {
    <#
    .SYNOPSIS
        Collecte les informations système de base (données statiques, mises en cache).

    .OUTPUTS
        Hashtable avec les informations système.
    #>
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop

        return @{
            Computer = @{
                hostname = $env:COMPUTERNAME
                domain = if ($cs.Domain) { $cs.Domain } else { $cs.Workgroup }
                manufacturer = $cs.Manufacturer
                model = $cs.Model
                serial_number = $bios.SerialNumber
            }
            OperatingSystem = @{
                name = $os.Caption
                version = $os.Version
                build_number = $os.BuildNumber
                architecture = $os.OSArchitecture
            }
            User = @{
                username = $env:USERNAME
                domain = $env:USERDOMAIN
            }
        }
    }
    catch {
        Write-Warning "Impossible de collecter les informations système de base: $_"
        return @{
            Computer = @{ hostname = $env:COMPUTERNAME }
            OperatingSystem = @{}
            User = @{ username = $env:USERNAME }
        }
    }
}

function Invoke-MetricCollection {
    <#
    .SYNOPSIS
        Collecte une métrique spécifique.

    .PARAMETER MetricName
        Nom de la métrique à collecter.

    .PARAMETER Category
        Catégorie de la métrique.

    .PARAMETER Timeout
        Timeout en secondes.

    .OUTPUTS
        Résultat de la collecte.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 30
    )

    try {
        # Déterminer quel collecteur utiliser selon la catégorie
        $result = switch ($Category) {
            'System' { Invoke-SystemMetricCollection -MetricName $MetricName }
            'Network' { Invoke-NetworkMetricCollection -MetricName $MetricName }
            'Security' { Invoke-SecurityMetricCollection -MetricName $MetricName }
            'Applications' { Invoke-ApplicationMetricCollection -MetricName $MetricName }
            'UserExperience' { Invoke-UserExperienceMetricCollection -MetricName $MetricName }
            'Hardware' { Invoke-HardwareMetricCollection -MetricName $MetricName }
            'Events' { Invoke-EventMetricCollection -MetricName $MetricName }
            default {
                [PSCustomObject]@{
                    MetricName = $MetricName
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    Success = $false
                    Error = "Catégorie inconnue: $Category"
                    Data = @{}
                }
            }
        }

        return $result
    }
    catch {
        return [PSCustomObject]@{
            MetricName = $MetricName
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Invoke-MultipleMetricCollection {
    <#
    .SYNOPSIS
        Collecte plusieurs métriques.

    .PARAMETER Metrics
        Array d'objets métriques à collecter.

    .PARAMETER Parallel
        Activer la collecte en parallèle.

    .PARAMETER MaxParallel
        Nombre maximum de collectes parallèles.

    .PARAMETER DelayMs
        Délai entre les collectes séquentielles (ms).

    .OUTPUTS
        Array des résultats de collecte.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Metrics,

        [Parameter(Mandatory = $false)]
        [bool]$Parallel = $false,

        [Parameter(Mandatory = $false)]
        [int]$MaxParallel = 5,

        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 100
    )

    $results = @()

    if ($Parallel -and $Metrics.Count -gt 1) {
        # Collecte en parallèle avec jobs
        $jobs = @()

        foreach ($metric in $Metrics) {
            $scriptBlock = {
                param($MetricName, $Category, $CollectorsPath)

                # Importer les modules nécessaires
                $systemPath = Join-Path $CollectorsPath 'SystemMetrics.psm1'
                $networkPath = Join-Path $CollectorsPath 'NetworkMetrics.psm1'
                $securityPath = Join-Path $CollectorsPath 'SecurityMetrics.psm1'

                if (Test-Path $systemPath) { Import-Module $systemPath -Force }
                if (Test-Path $networkPath) { Import-Module $networkPath -Force }
                if (Test-Path $securityPath) { Import-Module $securityPath -Force }

                # Collecter selon la catégorie
                switch ($Category) {
                    'System' { Invoke-SystemMetricCollection -MetricName $MetricName }
                    'Network' { Invoke-NetworkMetricCollection -MetricName $MetricName }
                    'Security' { Invoke-SecurityMetricCollection -MetricName $MetricName }
                    default {
                        [PSCustomObject]@{
                            MetricName = $MetricName
                            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                            Success = $false
                            Error = "Catégorie non supportée en parallèle: $Category"
                            Data = @{}
                        }
                    }
                }
            }

            $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $metric.Name, $metric.Category, $script:CollectorsPath
        }

        # Attendre les jobs avec timeout
        $completedJobs = $jobs | Wait-Job -Timeout 60

        foreach ($job in $jobs) {
            if ($job.State -eq 'Completed') {
                $result = Receive-Job -Job $job
                if ($result) {
                    $results += $result
                }
            }
            else {
                $results += [PSCustomObject]@{
                    MetricName = 'Unknown'
                    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                    Success = $false
                    Error = "Job timeout ou erreur"
                    Data = @{}
                }
            }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        # Collecte séquentielle
        foreach ($metric in $Metrics) {
            $result = Invoke-MetricCollection -MetricName $metric.Name -Category $metric.Category
            $results += $result

            # Délai entre les collectes pour limiter l'impact
            if ($DelayMs -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }
    }

    return $results
}

function Build-MetricsDocument {
    <#
    .SYNOPSIS
        Construit le document JSON complet avec toutes les métriques collectées.

    .PARAMETER MetricResults
        Résultats des collectes de métriques.

    .PARAMETER AgentId
        Identifiant de l'agent (optionnel).

    .OUTPUTS
        PSCustomObject représentant le document JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$MetricResults,

        [Parameter(Mandatory = $false)]
        [string]$AgentId = ''
    )

    # Grouper les résultats par catégorie
    $metricsByCategory = @{}

    foreach ($result in $MetricResults) {
        if ($result.Success -and $result.Data) {
            # Déterminer la catégorie depuis le nom de la métrique
            $category = Get-MetricCategory -MetricName $result.MetricName

            if (-not $metricsByCategory.ContainsKey($category)) {
                $metricsByCategory[$category] = @{}
            }

            # Aplatir les données dans la catégorie
            foreach ($key in $result.Data.Keys) {
                $metricsByCategory[$category][$key] = $result.Data[$key]
            }
        }
    }

    # Construire le document final
    $document = [ordered]@{
        '@timestamp' = (Get-Date).ToUniversalTime().ToString('o')
        agent_version = $script:CollectorVersion
        agent_id = if ($AgentId) { $AgentId } else { "$($env:COMPUTERNAME)_$([guid]::NewGuid().ToString().Substring(0,8))" }
        computer = if ($script:SystemInfo) { $script:SystemInfo.Computer } else { @{ hostname = $env:COMPUTERNAME } }
        os = if ($script:SystemInfo) { $script:SystemInfo.OperatingSystem } else { @{} }
        user = if ($script:SystemInfo) { $script:SystemInfo.User } else { @{ username = $env:USERNAME } }
        metrics = $metricsByCategory
        collection = @{
            metrics_collected = $MetricResults.Count
            metrics_successful = ($MetricResults | Where-Object { $_.Success }).Count
            metrics_failed = ($MetricResults | Where-Object { -not $_.Success }).Count
            collection_time = (Get-Date).ToUniversalTime().ToString('o')
        }
    }

    # Ajouter les erreurs si présentes
    $errors = $MetricResults | Where-Object { -not $_.Success } | ForEach-Object {
        @{
            metric = $_.MetricName
            error = $_.Error
        }
    }

    if ($errors.Count -gt 0) {
        $document['errors'] = $errors
    }

    return [PSCustomObject]$document
}

function Get-MetricCategory {
    <#
    .SYNOPSIS
        Détermine la catégorie d'une métrique basée sur son nom.

    .PARAMETER MetricName
        Nom de la métrique.

    .OUTPUTS
        Nom de la catégorie.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName
    )

    $categoryMappings = @{
        # System
        'CPUUsage' = 'system'
        'MemoryUsage' = 'system'
        'DiskSpace' = 'system'
        'DiskIO' = 'system'
        'SystemUptime' = 'system'

        # Network
        'InternetConnectivity' = 'network'
        'GatewayLatency' = 'network'
        'DNSResolution' = 'network'
        'ActiveConnections' = 'network'
        'WiFiSignalStrength' = 'network'

        # Security
        'AntivirusStatus' = 'security'
        'FirewallStatus' = 'security'
        'WindowsUpdateStatus' = 'security'
        'BitLockerStatus' = 'security'
        'PendingUpdates' = 'security'

        # Applications
        'RunningProcesses' = 'applications'
        'TopCPUConsumers' = 'applications'
        'TopMemoryConsumers' = 'applications'
        'ApplicationCrashes' = 'applications'
        'InstalledApplications' = 'applications'

        # UserExperience
        'BootTime' = 'experience'
        'LoginTime' = 'experience'
        'SessionUptime' = 'experience'

        # Hardware
        'ComputerModel' = 'hardware'
        'BatteryHealth' = 'hardware'
        'BatteryStatus' = 'hardware'

        # Events
        'SystemErrors' = 'events'
        'CriticalEvents' = 'events'
        'ApplicationErrors' = 'events'
    }

    if ($categoryMappings.ContainsKey($MetricName)) {
        return $categoryMappings[$MetricName]
    }

    return 'other'
}

function ConvertTo-MetricsJson {
    <#
    .SYNOPSIS
        Convertit le document de métriques en JSON.

    .PARAMETER Document
        Document de métriques.

    .PARAMETER Compress
        Compresser le JSON (pas de formatage).

    .OUTPUTS
        String JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Document,

        [Parameter(Mandatory = $false)]
        [bool]$Compress = $false
    )

    if ($Compress) {
        return $Document | ConvertTo-Json -Depth 10 -Compress
    }
    else {
        return $Document | ConvertTo-Json -Depth 10
    }
}

function Get-CollectorInfo {
    <#
    .SYNOPSIS
        Retourne les informations sur le collecteur.

    .OUTPUTS
        PSCustomObject avec les informations du collecteur.
    #>
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        Version = $script:CollectorVersion
        CollectorsPath = $script:CollectorsPath
        SystemInfoCached = ($null -ne $script:SystemInfo)
        Hostname = $env:COMPUTERNAME
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

# Fonctions de collecte placeholder pour les catégories non encore implémentées
function Invoke-ApplicationMetricCollection {
    param([string]$MetricName)
    return [PSCustomObject]@{
        MetricName = $MetricName
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Success = $false
        Error = "Collecteur Applications non implémenté"
        Data = @{}
    }
}

function Invoke-UserExperienceMetricCollection {
    param([string]$MetricName)
    return [PSCustomObject]@{
        MetricName = $MetricName
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Success = $false
        Error = "Collecteur UserExperience non implémenté"
        Data = @{}
    }
}

function Invoke-HardwareMetricCollection {
    param([string]$MetricName)
    return [PSCustomObject]@{
        MetricName = $MetricName
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Success = $false
        Error = "Collecteur Hardware non implémenté"
        Data = @{}
    }
}

function Invoke-EventMetricCollection {
    param([string]$MetricName)
    return [PSCustomObject]@{
        MetricName = $MetricName
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Success = $false
        Error = "Collecteur Events non implémenté"
        Data = @{}
    }
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Initialize-MetricsCollector',
    'Invoke-MetricCollection',
    'Invoke-MultipleMetricCollection',
    'Build-MetricsDocument',
    'ConvertTo-MetricsJson',
    'Get-CollectorInfo',
    'Get-BaseSystemInfo'
)
