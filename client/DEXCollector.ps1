#Requires -Version 5.1
<#
.SYNOPSIS
    DEX Collector - Agent de collecte de métriques d'expérience utilisateur digital.

.DESCRIPTION
    Script principal orchestrant la collecte de métriques système, réseau,
    applications et sécurité sur les endpoints Windows. Les données sont
    envoyées vers une stack ELK (Elasticsearch, Logstash, Kibana) pour
    analyse et visualisation.

.PARAMETER ConfigPath
    Chemin vers le dossier de configuration (défaut: .\config).

.PARAMETER RunOnce
    Exécuter une seule collecte puis quitter.

.PARAMETER TestMode
    Mode test : collecte et affiche les métriques sans envoyer.

.PARAMETER Verbose
    Activer les logs détaillés.

.EXAMPLE
    .\DEXCollector.ps1
    Démarre le collecteur en mode continu.

.EXAMPLE
    .\DEXCollector.ps1 -RunOnce -TestMode
    Exécute une collecte unique en mode test.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
    Requires: PowerShell 5.1+, Windows 10/11 ou Windows Server 2016+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = '',

    [Parameter(Mandatory = $false)]
    [switch]$RunOnce,

    [Parameter(Mandatory = $false)]
    [switch]$TestMode,

    [Parameter(Mandatory = $false)]
    [switch]$ShowStatus
)

#region Initialization

# Déterminer les chemins
$ScriptPath = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptPath)) {
    $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

if ([string]::IsNullOrEmpty($ConfigPath)) {
    $ConfigPath = Join-Path $ScriptPath 'config'
}

$ModulesPath = Join-Path $ScriptPath 'modules'
$CollectorsPath = Join-Path $ScriptPath 'collectors'

# Fichiers de configuration
$MetricsConfigFile = Join-Path $ConfigPath 'metrics.ini'
$CollectorConfigFile = Join-Path $ConfigPath 'collector.ini'

#endregion

#region Module Loading

function Import-DEXModules {
    <#
    .SYNOPSIS
        Charge tous les modules nécessaires au collecteur.
    #>
    [CmdletBinding()]
    param()

    $modules = @(
        @{ Name = 'ConfigParser'; Path = Join-Path $ModulesPath 'ConfigParser.psm1' },
        @{ Name = 'Logger'; Path = Join-Path $ModulesPath 'Logger.psm1' },
        @{ Name = 'MetricsScheduler'; Path = Join-Path $ModulesPath 'MetricsScheduler.psm1' },
        @{ Name = 'MetricsCollector'; Path = Join-Path $ModulesPath 'MetricsCollector.psm1' },
        @{ Name = 'DataSender'; Path = Join-Path $ModulesPath 'DataSender.psm1' }
    )

    $collectors = @(
        @{ Name = 'SystemMetrics'; Path = Join-Path $CollectorsPath 'SystemMetrics.psm1' },
        @{ Name = 'NetworkMetrics'; Path = Join-Path $CollectorsPath 'NetworkMetrics.psm1' },
        @{ Name = 'SecurityMetrics'; Path = Join-Path $CollectorsPath 'SecurityMetrics.psm1' }
    )

    $allModules = $modules + $collectors

    foreach ($module in $allModules) {
        if (Test-Path $module.Path) {
            try {
                Import-Module $module.Path -Force -ErrorAction Stop
                Write-Verbose "Module chargé: $($module.Name)"
            }
            catch {
                Write-Warning "Impossible de charger le module $($module.Name): $_"
                return $false
            }
        }
        else {
            Write-Warning "Module non trouvé: $($module.Path)"
            return $false
        }
    }

    return $true
}

#endregion

#region Main Functions

function Start-DEXCollector {
    <#
    .SYNOPSIS
        Point d'entrée principal du collecteur.
    #>
    [CmdletBinding()]
    param()

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  DEX Collector v1.0.0" -ForegroundColor Cyan
    Write-Host "  Monitoring Experience Utilisateur" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Vérifier les prérequis
    if (-not (Test-Prerequisites)) {
        Write-Error "Prérequis non satisfaits. Arrêt du collecteur."
        return
    }

    # Charger les modules
    Write-Host "[*] Chargement des modules..." -ForegroundColor Yellow
    if (-not (Import-DEXModules)) {
        Write-Error "Échec du chargement des modules. Arrêt du collecteur."
        return
    }
    Write-Host "[+] Modules chargés avec succès" -ForegroundColor Green

    # Charger la configuration
    Write-Host "[*] Chargement de la configuration..." -ForegroundColor Yellow
    $collectorConfig = Get-CollectorConfiguration -ConfigPath $CollectorConfigFile
    $metricsConfig = Get-MetricsConfiguration -ConfigPath $MetricsConfigFile

    if (-not $collectorConfig -or -not $metricsConfig) {
        Write-Error "Échec du chargement de la configuration. Arrêt du collecteur."
        return
    }
    Write-Host "[+] Configuration chargée" -ForegroundColor Green

    # Forcer le mode test si paramètre
    if ($TestMode) {
        $collectorConfig.DebugMode = $true
        $collectorConfig.ExportLocalJSON = $true
        Write-Host "[!] Mode TEST activé - Pas d'envoi vers Logstash" -ForegroundColor Yellow
    }

    # Initialiser le logger
    Initialize-Logger -LogPath $collectorConfig.LogPath `
                     -LogFileName $collectorConfig.LogFileName `
                     -LogLevel $collectorConfig.LogLevel `
                     -MaxLogSizeMB $collectorConfig.LogMaxSizeMB `
                     -LogRetentionDays $collectorConfig.LogRetentionDays

    Write-InfoLog -Message "DEX Collector démarré" -Category "Startup"

    # Initialiser le scheduler
    Initialize-Scheduler -MetricsConfig $metricsConfig | Out-Null
    Write-Host "[+] Scheduler initialisé" -ForegroundColor Green

    # Afficher les métriques configurées
    $enabledMetrics = Get-EnabledMetrics -MetricsConfig $metricsConfig
    Write-Host ""
    Write-Host "Métriques activées: $($enabledMetrics.Count)" -ForegroundColor Cyan
    foreach ($metric in $enabledMetrics) {
        $freq = if ($metric.IsEventDriven) { "event" } else { "$($metric.FrequencyMinutes)min" }
        Write-Host "  - $($metric.Name) [$($metric.Category)] ($freq)" -ForegroundColor Gray
    }
    Write-Host ""

    # Initialiser le collecteur
    Initialize-MetricsCollector -CollectorsPath $CollectorsPath -CollectorVersion $collectorConfig.CollectorVersion | Out-Null

    # Initialiser le DataSender
    Initialize-DataSender -Config $collectorConfig | Out-Null
    Write-Host "[+] DataSender initialisé" -ForegroundColor Green

    # Afficher le statut si demandé
    if ($ShowStatus) {
        Show-CollectorStatus -CollectorConfig $collectorConfig -MetricsConfig $metricsConfig
        return
    }

    Write-Host ""
    Write-Host "Démarrage de la collecte..." -ForegroundColor Green
    Write-InfoLog -Message "Collecte démarrée" -Category "Collection"

    # Boucle principale
    if ($RunOnce) {
        # Exécuter une seule collecte
        Invoke-CollectionCycle -MetricsConfig $metricsConfig -CollectorConfig $collectorConfig
        Write-Host ""
        Write-Host "[+] Collecte unique terminée" -ForegroundColor Green
    }
    else {
        # Boucle continue
        Start-CollectionLoop -MetricsConfig $metricsConfig -CollectorConfig $collectorConfig
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Vérifie les prérequis du système.
    #>
    [CmdletBinding()]
    param()

    $success = $true

    # Vérifier PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.1 ou supérieur requis. Version actuelle: $($PSVersionTable.PSVersion)"
        $success = $false
    }

    # Vérifier les chemins de configuration
    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Dossier de configuration non trouvé: $ConfigPath"
        $success = $false
    }

    if (-not (Test-Path $MetricsConfigFile)) {
        Write-Error "Fichier metrics.ini non trouvé: $MetricsConfigFile"
        $success = $false
    }

    if (-not (Test-Path $CollectorConfigFile)) {
        Write-Error "Fichier collector.ini non trouvé: $CollectorConfigFile"
        $success = $false
    }

    # Vérifier les dossiers modules
    if (-not (Test-Path $ModulesPath)) {
        Write-Error "Dossier modules non trouvé: $ModulesPath"
        $success = $false
    }

    if (-not (Test-Path $CollectorsPath)) {
        Write-Error "Dossier collectors non trouvé: $CollectorsPath"
        $success = $false
    }

    return $success
}

function Invoke-CollectionCycle {
    <#
    .SYNOPSIS
        Exécute un cycle de collecte de métriques.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CollectorConfig
    )

    $cycleStart = Get-Date
    Write-InfoLog -Message "Début du cycle de collecte" -Category "Collection"

    # Obtenir les métriques à collecter
    $dueMetrics = Get-MetricsDueForCollection

    if ($dueMetrics.Count -eq 0) {
        Write-Verbose "Aucune métrique à collecter ce cycle"
        return
    }

    Write-Host "[*] Collecte de $($dueMetrics.Count) métrique(s)..." -ForegroundColor Yellow

    # Préparer les objets métriques pour la collecte
    $metricsToCollect = @()
    foreach ($metricName in $dueMetrics) {
        $metric = $MetricsConfig.Metrics[$metricName]
        if ($metric) {
            $metricsToCollect += $metric
        }
    }

    # Collecter les métriques
    $results = Invoke-MultipleMetricCollection -Metrics $metricsToCollect `
                                               -Parallel $CollectorConfig.EnableParallelCollection `
                                               -DelayMs $CollectorConfig.CollectionDelayMs

    # Mettre à jour les timestamps de collecte
    foreach ($result in $results) {
        if ($result.Success) {
            Update-MetricLastCollected -MetricName $result.MetricName
        }
    }

    # Construire le document JSON
    $document = Build-MetricsDocument -MetricResults $results -AgentId $CollectorConfig.AgentId

    # Convertir en JSON
    $jsonData = ConvertTo-MetricsJson -Document $document -Compress $CollectorConfig.CompressData

    # Afficher un aperçu en mode test
    if ($CollectorConfig.DebugMode) {
        Write-Host ""
        Write-Host "=== Aperçu JSON ===" -ForegroundColor Cyan
        Write-Host ($document | ConvertTo-Json -Depth 3) -ForegroundColor Gray
        Write-Host "===================" -ForegroundColor Cyan
    }

    # Envoyer les données
    Write-Host "[*] Envoi des données..." -ForegroundColor Yellow
    $sendResult = Send-MetricsToLogstash -JsonData $jsonData

    if ($sendResult.Success) {
        Write-Host "[+] Données envoyées avec succès" -ForegroundColor Green
        Write-InfoLog -Message "Données envoyées: $($results.Count) métriques" -Category "Send"
    }
    else {
        if ($sendResult.Buffered) {
            Write-Host "[!] Données bufferisées localement" -ForegroundColor Yellow
            Write-WarningLog -Message "Données bufferisées: $($sendResult.Error)" -Category "Send"
        }
        else {
            Write-Host "[-] Échec de l'envoi: $($sendResult.Error)" -ForegroundColor Red
            Write-ErrorLog -Message "Échec envoi: $($sendResult.Error)" -Category "Send"
        }
    }

    $cycleDuration = (Get-Date) - $cycleStart
    Write-InfoLog -Message "Cycle terminé en $([math]::Round($cycleDuration.TotalSeconds, 2))s" -Category "Collection"
}

function Start-CollectionLoop {
    <#
    .SYNOPSIS
        Démarre la boucle de collecte continue.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CollectorConfig
    )

    Set-SchedulerRunning -Running $true
    $stopRequested = $false

    Write-Host ""
    Write-Host "Collecteur en cours d'exécution. Appuyez sur Ctrl+C pour arrêter." -ForegroundColor Cyan
    Write-Host ""

    # Traitement du Ctrl+C
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $stopRequested = $true
    }

    try {
        while (-not $stopRequested) {
            # Exécuter un cycle de collecte
            Invoke-CollectionCycle -MetricsConfig $MetricsConfig -CollectorConfig $CollectorConfig

            # Tenter d'envoyer les éléments bufferisés
            $bufferStatus = Get-DataSenderStatus
            if ($bufferStatus.BufferItemCount -gt 0) {
                Write-Host "[*] Traitement du buffer ($($bufferStatus.BufferItemCount) éléments)..." -ForegroundColor Yellow
                $bufferResult = Send-BufferedItems -MaxItems 5
                if ($bufferResult.Succeeded -gt 0) {
                    Write-Host "[+] $($bufferResult.Succeeded) élément(s) du buffer envoyé(s)" -ForegroundColor Green
                }
            }

            # Calculer le temps de sommeil
            $sleepSeconds = Get-SleepDuration -MaxSleepSeconds 60

            if ($sleepSeconds -gt 0) {
                Write-Verbose "Prochaine collecte dans $sleepSeconds secondes..."
                Start-Sleep -Seconds $sleepSeconds
            }

            # Vérifier si on doit recharger la configuration
            if ($CollectorConfig.AutoReloadConfig) {
                $newMetricsConfig = Get-MetricsConfiguration -ConfigPath $MetricsConfigFile
                if ($newMetricsConfig.Metadata.ConfigVersion -ne $MetricsConfig.Metadata.ConfigVersion) {
                    Write-Host "[!] Configuration rechargée (v$($newMetricsConfig.Metadata.ConfigVersion))" -ForegroundColor Yellow
                    $MetricsConfig = $newMetricsConfig
                    Initialize-Scheduler -MetricsConfig $MetricsConfig | Out-Null
                    Write-InfoLog -Message "Configuration rechargée" -Category "Config"
                }
            }
        }
    }
    catch {
        Write-ErrorLog -Message "Erreur dans la boucle de collecte: $_" -Category "Error"
    }
    finally {
        Set-SchedulerRunning -Running $false
        Write-InfoLog -Message "Collecteur arrêté" -Category "Shutdown"
        Write-Host ""
        Write-Host "[*] Collecteur arrêté" -ForegroundColor Yellow
    }
}

function Show-CollectorStatus {
    <#
    .SYNOPSIS
        Affiche le statut détaillé du collecteur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CollectorConfig,

        [Parameter(Mandatory = $true)]
        [hashtable]$MetricsConfig
    )

    Write-Host ""
    Write-Host "=== État du Collecteur ===" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Version: $($CollectorConfig.CollectorVersion)"
    Write-Host "  Niveau de log: $($CollectorConfig.LogLevel)"
    Write-Host "  Mode debug: $($CollectorConfig.DebugMode)"
    Write-Host ""

    Write-Host "Logstash:" -ForegroundColor Yellow
    Write-Host "  Endpoint: $($CollectorConfig.LogstashEndpoint)"
    Write-Host "  Auth: $($CollectorConfig.LogstashUseAuth)"
    Write-Host ""

    Write-Host "Buffer:" -ForegroundColor Yellow
    $bufferStatus = Get-DataSenderStatus
    Write-Host "  Activé: $($bufferStatus.BufferEnabled)"
    Write-Host "  Chemin: $($bufferStatus.BufferPath)"
    Write-Host "  Éléments en attente: $($bufferStatus.BufferItemCount)"
    Write-Host "  Taille: $($bufferStatus.BufferSizeMB) MB"
    Write-Host ""

    Write-Host "Métriques:" -ForegroundColor Yellow
    $enabledMetrics = Get-EnabledMetrics -MetricsConfig $MetricsConfig
    Write-Host "  Activées: $($enabledMetrics.Count)"

    $byCategory = $enabledMetrics | Group-Object -Property Category
    foreach ($cat in $byCategory) {
        Write-Host "  - $($cat.Name): $($cat.Count)"
    }
    Write-Host ""

    Write-Host "Groupes de fréquence:" -ForegroundColor Yellow
    $groups = Get-FrequencyGroups
    foreach ($freq in ($groups.Keys | Sort-Object)) {
        Write-Host "  - $freq min: $($groups[$freq].Count) métrique(s)"
    }
    Write-Host ""
}

#endregion

#region Entry Point

# Démarrer le collecteur
Start-DEXCollector

#endregion
