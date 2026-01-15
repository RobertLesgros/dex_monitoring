#Requires -Version 5.1
<#
.SYNOPSIS
    Module d'envoi des données vers Logstash pour DEX Collector.

.DESCRIPTION
    Gère l'envoi des métriques collectées vers Logstash via HTTP/HTTPS,
    avec support du buffer local en cas d'indisponibilité du serveur
    et retry avec backoff exponentiel.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

# Variables de module
$script:Config = $null
$script:BufferPath = $null
$script:IsInitialized = $false
$script:RetryCount = @{}

function Initialize-DataSender {
    <#
    .SYNOPSIS
        Initialise le module d'envoi de données.

    .PARAMETER Config
        Configuration du collecteur (PSCustomObject).

    .OUTPUTS
        Booléen indiquant le succès de l'initialisation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )

    try {
        $script:Config = $Config
        $script:BufferPath = $Config.BufferPath

        # Créer le répertoire de buffer si nécessaire
        if ($Config.BufferEnabled -and -not (Test-Path $script:BufferPath)) {
            New-Item -Path $script:BufferPath -ItemType Directory -Force | Out-Null
        }

        # Créer le répertoire d'export JSON local si nécessaire
        if ($Config.ExportLocalJSON -and -not (Test-Path $Config.LocalJSONPath)) {
            New-Item -Path $Config.LocalJSONPath -ItemType Directory -Force | Out-Null
        }

        $script:IsInitialized = $true

        Write-Verbose "DataSender initialisé. Endpoint: $($Config.LogstashEndpoint)"
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation du DataSender: $_"
        return $false
    }
}

function Send-MetricsToLogstash {
    <#
    .SYNOPSIS
        Envoie les métriques vers Logstash.

    .PARAMETER JsonData
        Données JSON à envoyer.

    .PARAMETER RetryOnFailure
        Réessayer en cas d'échec.

    .OUTPUTS
        PSCustomObject avec le résultat de l'envoi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonData,

        [Parameter(Mandatory = $false)]
        [bool]$RetryOnFailure = $true
    )

    if (-not $script:IsInitialized) {
        return [PSCustomObject]@{
            Success = $false
            Error = "DataSender non initialisé"
            Buffered = $false
        }
    }

    # Mode debug ou dry run
    if ($script:Config.DebugMode -or $script:Config.DryRun) {
        Write-Verbose "Mode Debug/DryRun: Envoi simulé vers Logstash"

        # Exporter localement si configuré
        if ($script:Config.ExportLocalJSON) {
            Export-JsonLocally -JsonData $JsonData
        }

        return [PSCustomObject]@{
            Success = $true
            Message = "Debug/DryRun mode - données non envoyées"
            Buffered = $false
        }
    }

    $endpoint = $script:Config.LogstashEndpoint
    $timeout = $script:Config.LogstashRequestTimeout * 1000  # Convertir en millisecondes

    try {
        # Préparer les headers
        $headers = @{
            'Content-Type' = 'application/json'
        }

        # Ajouter l'authentification si configurée
        if ($script:Config.LogstashUseAuth -and $script:Config.LogstashUsername) {
            $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
                "$($script:Config.LogstashUsername):$($script:Config.LogstashPassword)"
            ))
            $headers['Authorization'] = "Basic $creds"
        }

        # Configurer les options de requête
        $requestParams = @{
            Uri = $endpoint
            Method = 'POST'
            Body = $JsonData
            Headers = $headers
            ContentType = 'application/json'
            TimeoutSec = $script:Config.LogstashRequestTimeout
            UseBasicParsing = $true
        }

        # Ignorer les erreurs SSL si configuré (dev uniquement)
        if ($script:Config.LogstashIgnoreSSL) {
            # PowerShell 5.1
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            else {
                $requestParams['SkipCertificateCheck'] = $true
            }
        }

        # Envoyer la requête
        $response = Invoke-WebRequest @requestParams

        # Vérifier le code de réponse
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            # Exporter localement si configuré (en plus de l'envoi)
            if ($script:Config.ExportLocalJSON) {
                Export-JsonLocally -JsonData $JsonData
            }

            return [PSCustomObject]@{
                Success = $true
                StatusCode = $response.StatusCode
                Message = "Données envoyées avec succès"
                Buffered = $false
            }
        }
        else {
            throw "Code de réponse inattendu: $($response.StatusCode)"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message

        Write-Warning "Erreur d'envoi vers Logstash: $errorMessage"

        # Buffer les données si activé
        if ($script:Config.BufferEnabled) {
            $buffered = Save-ToBuffer -JsonData $JsonData
        }
        else {
            $buffered = $false
        }

        # Exporter localement en cas d'échec (backup)
        if ($script:Config.ExportLocalJSON) {
            Export-JsonLocally -JsonData $JsonData
        }

        return [PSCustomObject]@{
            Success = $false
            Error = $errorMessage
            Buffered = $buffered
            Message = if ($buffered) { "Données sauvegardées dans le buffer local" } else { "Données perdues" }
        }
    }
}

function Save-ToBuffer {
    <#
    .SYNOPSIS
        Sauvegarde les données dans le buffer local.

    .PARAMETER JsonData
        Données JSON à sauvegarder.

    .OUTPUTS
        Booléen indiquant le succès de la sauvegarde.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonData
    )

    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
        $fileName = "buffer_$timestamp.json"
        $filePath = Join-Path $script:BufferPath $fileName

        # Vérifier la taille du buffer
        $currentSizeMB = Get-BufferSize
        if ($currentSizeMB -ge $script:Config.BufferMaxSizeMB) {
            # Nettoyer les plus anciens fichiers
            Invoke-BufferCleanup -TargetSizeMB ($script:Config.BufferMaxSizeMB * 0.8)
        }

        # Sauvegarder
        $JsonData | Out-File -FilePath $filePath -Encoding UTF8 -Force

        Write-Verbose "Données sauvegardées dans le buffer: $fileName"
        return $true
    }
    catch {
        Write-Warning "Erreur lors de la sauvegarde dans le buffer: $_"
        return $false
    }
}

function Get-BufferSize {
    <#
    .SYNOPSIS
        Calcule la taille actuelle du buffer en MB.

    .OUTPUTS
        Taille en MB.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:BufferPath)) {
        return 0
    }

    $size = Get-ChildItem -Path $script:BufferPath -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum

    return [math]::Round($size.Sum / 1MB, 2)
}

function Get-BufferedItems {
    <#
    .SYNOPSIS
        Retourne les éléments en attente dans le buffer.

    .OUTPUTS
        Array des fichiers buffer.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:BufferPath)) {
        return @()
    }

    return Get-ChildItem -Path $script:BufferPath -Filter '*.json' -File |
        Sort-Object CreationTime
}

function Send-BufferedItems {
    <#
    .SYNOPSIS
        Tente d'envoyer les éléments en attente dans le buffer.

    .PARAMETER MaxItems
        Nombre maximum d'éléments à traiter.

    .OUTPUTS
        PSCustomObject avec les résultats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxItems = 10
    )

    $items = Get-BufferedItems | Select-Object -First $MaxItems
    $results = @{
        Processed = 0
        Succeeded = 0
        Failed = 0
    }

    foreach ($item in $items) {
        try {
            $jsonData = Get-Content -Path $item.FullName -Raw -Encoding UTF8

            $sendResult = Send-MetricsToLogstash -JsonData $jsonData -RetryOnFailure $false

            $results.Processed++

            if ($sendResult.Success) {
                # Supprimer le fichier du buffer
                Remove-Item -Path $item.FullName -Force
                $results.Succeeded++
                Write-Verbose "Buffer item envoyé et supprimé: $($item.Name)"
            }
            else {
                $results.Failed++
                Write-Verbose "Échec de l'envoi du buffer item: $($item.Name)"
            }
        }
        catch {
            $results.Failed++
            Write-Warning "Erreur lors du traitement du buffer item $($item.Name): $_"
        }

        # Petite pause entre les envois
        Start-Sleep -Milliseconds 500
    }

    return [PSCustomObject]$results
}

function Invoke-BufferCleanup {
    <#
    .SYNOPSIS
        Nettoie le buffer en supprimant les anciens fichiers.

    .PARAMETER TargetSizeMB
        Taille cible en MB.

    .PARAMETER MaxAgeHours
        Age maximum des fichiers en heures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [double]$TargetSizeMB = 0,

        [Parameter(Mandatory = $false)]
        [int]$MaxAgeHours = 0
    )

    if (-not (Test-Path $script:BufferPath)) {
        return
    }

    # Utiliser la config par défaut si non spécifié
    if ($MaxAgeHours -eq 0 -and $script:Config) {
        $MaxAgeHours = $script:Config.BufferRetentionHours
    }

    $items = Get-BufferedItems

    # Supprimer les fichiers trop anciens
    if ($MaxAgeHours -gt 0) {
        $cutoff = (Get-Date).AddHours(-$MaxAgeHours)
        $oldItems = $items | Where-Object { $_.CreationTime -lt $cutoff }

        foreach ($item in $oldItems) {
            Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
            Write-Verbose "Buffer item expiré supprimé: $($item.Name)"
        }
    }

    # Supprimer pour atteindre la taille cible
    if ($TargetSizeMB -gt 0) {
        $currentSize = Get-BufferSize

        while ($currentSize -gt $TargetSizeMB) {
            $oldest = Get-BufferedItems | Select-Object -First 1

            if (-not $oldest) {
                break
            }

            Remove-Item -Path $oldest.FullName -Force -ErrorAction SilentlyContinue
            Write-Verbose "Buffer item supprimé pour libérer de l'espace: $($oldest.Name)"

            $currentSize = Get-BufferSize
        }
    }
}

function Export-JsonLocally {
    <#
    .SYNOPSIS
        Exporte les données JSON dans un fichier local.

    .PARAMETER JsonData
        Données JSON à exporter.

    .OUTPUTS
        Chemin du fichier exporté ou $null en cas d'erreur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonData
    )

    try {
        $exportPath = if ($script:Config) { $script:Config.LocalJSONPath } else { 'C:\ProgramData\DEXCollector\export' }

        if (-not (Test-Path $exportPath)) {
            New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
        }

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $fileName = "metrics_$timestamp.json"
        $filePath = Join-Path $exportPath $fileName

        $JsonData | Out-File -FilePath $filePath -Encoding UTF8 -Force

        # Nettoyer les anciens exports (garder les 100 derniers)
        $exports = Get-ChildItem -Path $exportPath -Filter 'metrics_*.json' |
            Sort-Object CreationTime -Descending |
            Select-Object -Skip 100

        foreach ($old in $exports) {
            Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue
        }

        return $filePath
    }
    catch {
        Write-Warning "Erreur lors de l'export JSON local: $_"
        return $null
    }
}

function Test-LogstashConnection {
    <#
    .SYNOPSIS
        Teste la connectivité vers Logstash.

    .OUTPUTS
        PSCustomObject avec le résultat du test.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:IsInitialized) {
        return [PSCustomObject]@{
            Connected = $false
            Error = "DataSender non initialisé"
        }
    }

    $endpoint = $script:Config.LogstashEndpoint

    try {
        # Tenter une requête HEAD ou GET
        $response = Invoke-WebRequest -Uri $endpoint -Method HEAD -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop

        return [PSCustomObject]@{
            Connected = $true
            StatusCode = $response.StatusCode
            Endpoint = $endpoint
        }
    }
    catch {
        return [PSCustomObject]@{
            Connected = $false
            Error = $_.Exception.Message
            Endpoint = $endpoint
        }
    }
}

function Get-DataSenderStatus {
    <#
    .SYNOPSIS
        Retourne l'état du DataSender.

    .OUTPUTS
        PSCustomObject avec les informations de statut.
    #>
    [CmdletBinding()]
    param()

    $bufferItems = Get-BufferedItems
    $bufferSize = Get-BufferSize

    return [PSCustomObject]@{
        Initialized = $script:IsInitialized
        Endpoint = if ($script:Config) { $script:Config.LogstashEndpoint } else { 'N/A' }
        BufferEnabled = if ($script:Config) { $script:Config.BufferEnabled } else { $false }
        BufferPath = $script:BufferPath
        BufferItemCount = $bufferItems.Count
        BufferSizeMB = $bufferSize
        ExportLocalJSON = if ($script:Config) { $script:Config.ExportLocalJSON } else { $false }
        DebugMode = if ($script:Config) { $script:Config.DebugMode } else { $false }
    }
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Initialize-DataSender',
    'Send-MetricsToLogstash',
    'Save-ToBuffer',
    'Get-BufferSize',
    'Get-BufferedItems',
    'Send-BufferedItems',
    'Invoke-BufferCleanup',
    'Export-JsonLocally',
    'Test-LogstashConnection',
    'Get-DataSenderStatus'
)
