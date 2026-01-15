#Requires -Version 5.1
<#
.SYNOPSIS
    Module de parsing des fichiers de configuration INI pour DEX Collector.

.DESCRIPTION
    Ce module fournit des fonctions pour lire, parser et valider les fichiers
    de configuration INI utilisés par le collecteur DEX.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

# Variables de module
$script:CachedMetricsConfig = $null
$script:CachedCollectorConfig = $null
$script:LastMetricsConfigLoad = [DateTime]::MinValue
$script:LastCollectorConfigLoad = [DateTime]::MinValue

function Read-IniFile {
    <#
    .SYNOPSIS
        Lit et parse un fichier INI en hashtable.

    .PARAMETER Path
        Chemin vers le fichier INI.

    .OUTPUTS
        Hashtable avec les sections et leurs clés/valeurs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $ini = @{}
    $currentSection = "Default"

    try {
        $content = Get-Content -Path $Path -Encoding UTF8 -ErrorAction Stop

        foreach ($line in $content) {
            $line = $line.Trim()

            # Ignorer les lignes vides et les commentaires
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#') -or $line.StartsWith(';')) {
                continue
            }

            # Détecter une section [SectionName]
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $matches[1].Trim()
                if (-not $ini.ContainsKey($currentSection)) {
                    $ini[$currentSection] = @{}
                }
                continue
            }

            # Parser une clé = valeur
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()

                # Initialiser la section si nécessaire
                if (-not $ini.ContainsKey($currentSection)) {
                    $ini[$currentSection] = @{}
                }

                $ini[$currentSection][$key] = $value
            }
        }

        return $ini
    }
    catch {
        Write-Error "Erreur lors de la lecture du fichier INI '$Path': $_"
        return $null
    }
}

function Get-MetricsConfiguration {
    <#
    .SYNOPSIS
        Charge et parse la configuration des métriques depuis metrics.ini.

    .PARAMETER ConfigPath
        Chemin vers le fichier metrics.ini.

    .PARAMETER ForceReload
        Force le rechargement même si le cache est valide.

    .OUTPUTS
        Hashtable contenant la configuration des métriques par section.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReload
    )

    # Vérifier le cache
    if (-not $ForceReload -and $script:CachedMetricsConfig -and (Test-Path $ConfigPath)) {
        $lastWrite = (Get-Item $ConfigPath).LastWriteTime
        if ($lastWrite -le $script:LastMetricsConfigLoad) {
            return $script:CachedMetricsConfig
        }
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Le fichier de configuration des métriques n'existe pas: $ConfigPath"
        return $null
    }

    $rawConfig = Read-IniFile -Path $ConfigPath
    if (-not $rawConfig) {
        return $null
    }

    $metricsConfig = @{
        Metadata = @{}
        Metrics = @{}
    }

    foreach ($section in $rawConfig.Keys) {
        if ($section -eq "Metadata") {
            $metricsConfig.Metadata = $rawConfig[$section]
            continue
        }

        foreach ($metricName in $rawConfig[$section].Keys) {
            $metricValue = $rawConfig[$section][$metricName]
            $parsedMetric = ConvertTo-MetricObject -MetricName $metricName -MetricValue $metricValue -Category $section

            if ($parsedMetric) {
                $metricsConfig.Metrics[$metricName] = $parsedMetric
            }
        }
    }

    # Mettre à jour le cache
    $script:CachedMetricsConfig = $metricsConfig
    $script:LastMetricsConfigLoad = Get-Date

    return $metricsConfig
}

function ConvertTo-MetricObject {
    <#
    .SYNOPSIS
        Convertit une ligne de configuration métrique en objet structuré.

    .PARAMETER MetricName
        Nom de la métrique.

    .PARAMETER MetricValue
        Valeur de la configuration (format: "enabled, frequency, priority").

    .PARAMETER Category
        Catégorie/section de la métrique.

    .OUTPUTS
        PSCustomObject avec les propriétés de la métrique.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName,

        [Parameter(Mandatory = $true)]
        [string]$MetricValue,

        [Parameter(Mandatory = $true)]
        [string]$Category
    )

    try {
        # Parser "true, 5, high" ou "false, 10, medium"
        $parts = $MetricValue -split ',' | ForEach-Object { $_.Trim() }

        if ($parts.Count -lt 3) {
            Write-Warning "Format invalide pour la métrique '$MetricName': '$MetricValue'. Format attendu: 'enabled, frequency, priority'"
            return $null
        }

        $enabled = [bool]::Parse($parts[0])
        $frequency = [int]::Parse($parts[1])
        $priority = $parts[2].ToLower()

        # Valider la priorité
        if ($priority -notin @('high', 'medium', 'low')) {
            Write-Warning "Priorité invalide pour '$MetricName': '$priority'. Utilisation de 'medium' par défaut."
            $priority = 'medium'
        }

        return [PSCustomObject]@{
            Name = $MetricName
            Category = $Category
            Enabled = $enabled
            FrequencyMinutes = $frequency
            Priority = $priority
            IsEventDriven = ($frequency -eq 0)
            LastCollected = [DateTime]::MinValue
        }
    }
    catch {
        Write-Warning "Erreur lors du parsing de la métrique '$MetricName': $_"
        return $null
    }
}

function Get-CollectorConfiguration {
    <#
    .SYNOPSIS
        Charge et parse la configuration générale du collecteur depuis collector.ini.

    .PARAMETER ConfigPath
        Chemin vers le fichier collector.ini.

    .PARAMETER ForceReload
        Force le rechargement même si le cache est valide.

    .OUTPUTS
        PSCustomObject contenant la configuration du collecteur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [switch]$ForceReload
    )

    # Vérifier le cache
    if (-not $ForceReload -and $script:CachedCollectorConfig -and (Test-Path $ConfigPath)) {
        $lastWrite = (Get-Item $ConfigPath).LastWriteTime
        if ($lastWrite -le $script:LastCollectorConfigLoad) {
            return $script:CachedCollectorConfig
        }
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Le fichier de configuration du collecteur n'existe pas: $ConfigPath"
        return $null
    }

    $rawConfig = Read-IniFile -Path $ConfigPath
    if (-not $rawConfig) {
        return $null
    }

    # Construire l'objet de configuration avec des valeurs par défaut
    $config = [PSCustomObject]@{
        # General
        CollectorVersion = Get-ConfigValue -Config $rawConfig -Section 'General' -Key 'CollectorVersion' -Default '1.0.0'
        LogLevel = Get-ConfigValue -Config $rawConfig -Section 'General' -Key 'LogLevel' -Default 'INFO'
        AgentId = Get-ConfigValue -Config $rawConfig -Section 'General' -Key 'AgentId' -Default ''

        # Collection
        BaseFrequency = [int](Get-ConfigValue -Config $rawConfig -Section 'Collection' -Key 'BaseFrequency' -Default '5')
        MaxParallelCollections = [int](Get-ConfigValue -Config $rawConfig -Section 'Collection' -Key 'MaxParallelCollections' -Default '5')
        DefaultTimeout = [int](Get-ConfigValue -Config $rawConfig -Section 'Collection' -Key 'DefaultTimeout' -Default '30')

        # Logstash
        LogstashEndpoint = Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'Endpoint' -Default 'http://localhost:5044'
        LogstashUseAuth = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'UseAuthentication' -Default 'false'))
        LogstashUsername = Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'Username' -Default ''
        LogstashPassword = Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'Password' -Default ''
        LogstashConnectionTimeout = [int](Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'ConnectionTimeout' -Default '30')
        LogstashRequestTimeout = [int](Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'RequestTimeout' -Default '60')
        LogstashUseHTTPS = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'UseHTTPS' -Default 'false'))
        LogstashIgnoreSSL = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Logstash' -Key 'IgnoreSSLErrors' -Default 'false'))

        # Buffer
        BufferEnabled = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'EnableBuffer' -Default 'true'))
        BufferPath = Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'BufferPath' -Default 'C:\ProgramData\DEXCollector\buffer'
        BufferMaxSizeMB = [int](Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'MaxBufferSizeMB' -Default '100')
        BufferRetentionHours = [int](Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'BufferRetentionHours' -Default '24')
        BufferRetryInterval = [int](Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'RetryIntervalSeconds' -Default '60')
        BufferMaxRetries = [int](Get-ConfigValue -Config $rawConfig -Section 'Buffer' -Key 'MaxRetries' -Default '5')

        # Logging
        LogPath = Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'LogPath' -Default 'C:\ProgramData\DEXCollector\logs'
        LogFileName = Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'LogFileName' -Default 'dexcollector.log'
        LogRetentionDays = [int](Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'LogRetentionDays' -Default '7')
        LogMaxSizeMB = [int](Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'MaxLogFileSizeMB' -Default '10')
        LogIncludeTimestamp = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'IncludeTimestamp' -Default 'true'))
        LogTimestampFormat = Get-ConfigValue -Config $rawConfig -Section 'Logging' -Key 'TimestampFormat' -Default 'yyyy-MM-dd HH:mm:ss'

        # Performance
        MaxCPUUsage = [int](Get-ConfigValue -Config $rawConfig -Section 'Performance' -Key 'MaxCPUUsage' -Default '5')
        CollectionDelayMs = [int](Get-ConfigValue -Config $rawConfig -Section 'Performance' -Key 'CollectionDelayMs' -Default '100')
        MetricTimeout = [int](Get-ConfigValue -Config $rawConfig -Section 'Performance' -Key 'MetricTimeoutSeconds' -Default '30')
        EnableParallelCollection = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Performance' -Key 'EnableParallelCollection' -Default 'true'))

        # HotReload
        AutoReloadConfig = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'HotReload' -Key 'AutoReloadConfig' -Default 'true'))
        ConfigCheckInterval = [int](Get-ConfigValue -Config $rawConfig -Section 'HotReload' -Key 'ConfigCheckIntervalMinutes' -Default '5')
        WatchMetricsConfig = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'HotReload' -Key 'WatchMetricsConfig' -Default 'true'))
        WatchCollectorConfig = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'HotReload' -Key 'WatchCollectorConfig' -Default 'true'))

        # Identification
        ComputerName = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'ComputerName' -Default ''
        Domain = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'Domain' -Default ''
        OrganizationalUnit = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'OrganizationalUnit' -Default ''
        SiteName = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'SiteName' -Default ''
        MachineTag = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'MachineTag' -Default ''
        Profile = Get-ConfigValue -Config $rawConfig -Section 'Identification' -Key 'Profile' -Default ''

        # Advanced
        DebugMode = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Advanced' -Key 'DebugMode' -Default 'false'))
        DryRun = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Advanced' -Key 'DryRun' -Default 'false'))
        ExportLocalJSON = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Advanced' -Key 'ExportLocalJSON' -Default 'true'))
        LocalJSONPath = Get-ConfigValue -Config $rawConfig -Section 'Advanced' -Key 'LocalJSONPath' -Default 'C:\ProgramData\DEXCollector\export'
        CompressData = [bool]::Parse((Get-ConfigValue -Config $rawConfig -Section 'Advanced' -Key 'CompressData' -Default 'false'))
    }

    # Mettre à jour le cache
    $script:CachedCollectorConfig = $config
    $script:LastCollectorConfigLoad = Get-Date

    return $config
}

function Get-ConfigValue {
    <#
    .SYNOPSIS
        Récupère une valeur de configuration avec gestion des valeurs par défaut.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [string]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $false)]
        [string]$Default = ''
    )

    if ($Config.ContainsKey($Section) -and $Config[$Section].ContainsKey($Key)) {
        $value = $Config[$Section][$Key]
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return $Default
}

function Get-EnabledMetrics {
    <#
    .SYNOPSIS
        Retourne uniquement les métriques activées, triées par priorité et fréquence.

    .PARAMETER MetricsConfig
        Configuration des métriques (résultat de Get-MetricsConfiguration).

    .OUTPUTS
        Array de métriques activées.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig
    )

    $priorityOrder = @{
        'high' = 1
        'medium' = 2
        'low' = 3
    }

    $enabledMetrics = $MetricsConfig.Metrics.Values |
        Where-Object { $_.Enabled } |
        Sort-Object @{Expression = { $priorityOrder[$_.Priority] }}, FrequencyMinutes

    return $enabledMetrics
}

function Get-MetricsByFrequency {
    <#
    .SYNOPSIS
        Groupe les métriques par fréquence de collecte.

    .PARAMETER MetricsConfig
        Configuration des métriques.

    .OUTPUTS
        Hashtable avec les fréquences comme clés et les métriques comme valeurs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig
    )

    $enabledMetrics = Get-EnabledMetrics -MetricsConfig $MetricsConfig
    $groupedMetrics = @{}

    foreach ($metric in $enabledMetrics) {
        $frequency = $metric.FrequencyMinutes

        if (-not $groupedMetrics.ContainsKey($frequency)) {
            $groupedMetrics[$frequency] = @()
        }

        $groupedMetrics[$frequency] += $metric
    }

    return $groupedMetrics
}

function Clear-ConfigCache {
    <#
    .SYNOPSIS
        Vide le cache de configuration pour forcer un rechargement.
    #>
    [CmdletBinding()]
    param()

    $script:CachedMetricsConfig = $null
    $script:CachedCollectorConfig = $null
    $script:LastMetricsConfigLoad = [DateTime]::MinValue
    $script:LastCollectorConfigLoad = [DateTime]::MinValue

    Write-Verbose "Cache de configuration vidé."
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Read-IniFile',
    'Get-MetricsConfiguration',
    'Get-CollectorConfiguration',
    'Get-EnabledMetrics',
    'Get-MetricsByFrequency',
    'Clear-ConfigCache'
)
