#Requires -Version 5.1
<#
.SYNOPSIS
    Module de logging pour DEX Collector.

.DESCRIPTION
    Fournit des fonctions de logging structuré avec support de rotation,
    niveaux de log et formatage personnalisable.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

# Variables de module
$script:LogPath = $null
$script:LogFileName = 'dexcollector.log'
$script:LogLevel = 'INFO'
$script:MaxLogSizeMB = 10
$script:LogRetentionDays = 7
$script:TimestampFormat = 'yyyy-MM-dd HH:mm:ss'
$script:IsInitialized = $false

# Niveaux de log avec leur priorité
$script:LogLevels = @{
    'DEBUG' = 0
    'INFO' = 1
    'WARNING' = 2
    'ERROR' = 3
    'CRITICAL' = 4
}

function Initialize-Logger {
    <#
    .SYNOPSIS
        Initialise le module de logging avec la configuration spécifiée.

    .PARAMETER LogPath
        Chemin du répertoire de logs.

    .PARAMETER LogFileName
        Nom du fichier de log.

    .PARAMETER LogLevel
        Niveau minimum de log (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    .PARAMETER MaxLogSizeMB
        Taille maximum du fichier de log en MB avant rotation.

    .PARAMETER LogRetentionDays
        Nombre de jours de rétention des logs.

    .PARAMETER TimestampFormat
        Format du timestamp dans les logs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = 'C:\ProgramData\DEXCollector\logs',

        [Parameter(Mandatory = $false)]
        [string]$LogFileName = 'dexcollector.log',

        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$LogLevel = 'INFO',

        [Parameter(Mandatory = $false)]
        [int]$MaxLogSizeMB = 10,

        [Parameter(Mandatory = $false)]
        [int]$LogRetentionDays = 7,

        [Parameter(Mandatory = $false)]
        [string]$TimestampFormat = 'yyyy-MM-dd HH:mm:ss'
    )

    $script:LogPath = $LogPath
    $script:LogFileName = $LogFileName
    $script:LogLevel = $LogLevel.ToUpper()
    $script:MaxLogSizeMB = $MaxLogSizeMB
    $script:LogRetentionDays = $LogRetentionDays
    $script:TimestampFormat = $TimestampFormat

    # Créer le répertoire de logs s'il n'existe pas
    if (-not (Test-Path $script:LogPath)) {
        try {
            New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
        }
        catch {
            Write-Warning "Impossible de créer le répertoire de logs: $($script:LogPath). $_"
            return $false
        }
    }

    $script:IsInitialized = $true

    # Nettoyer les vieux logs au démarrage
    Remove-OldLogs

    Write-Log -Level 'INFO' -Message "Logger initialisé. Niveau: $script:LogLevel, Chemin: $script:LogPath"

    return $true
}

function Write-Log {
    <#
    .SYNOPSIS
        Écrit un message dans le fichier de log.

    .PARAMETER Level
        Niveau du message (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    .PARAMETER Message
        Message à logger.

    .PARAMETER Category
        Catégorie optionnelle pour le contexte.

    .PARAMETER Exception
        Exception optionnelle à inclure dans le log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = '',

        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception = $null
    )

    # Vérifier si le niveau est suffisant pour être loggé
    if ($script:LogLevels[$Level] -lt $script:LogLevels[$script:LogLevel]) {
        return
    }

    # Si le logger n'est pas initialisé, utiliser les valeurs par défaut
    if (-not $script:IsInitialized) {
        Initialize-Logger | Out-Null
    }

    # Construire le message de log
    $timestamp = Get-Date -Format $script:TimestampFormat
    $categoryPart = if ($Category) { "[$Category] " } else { "" }
    $logMessage = "[$timestamp] [$Level] $categoryPart$Message"

    # Ajouter les détails de l'exception si présente
    if ($Exception) {
        $logMessage += "`n  Exception: $($Exception.GetType().FullName)"
        $logMessage += "`n  Message: $($Exception.Message)"
        if ($Exception.StackTrace) {
            $logMessage += "`n  StackTrace: $($Exception.StackTrace)"
        }
    }

    # Chemin complet du fichier de log
    $logFilePath = Join-Path $script:LogPath $script:LogFileName

    try {
        # Vérifier si rotation nécessaire
        if (Test-Path $logFilePath) {
            $logFile = Get-Item $logFilePath
            $sizeMB = $logFile.Length / 1MB

            if ($sizeMB -ge $script:MaxLogSizeMB) {
                Invoke-LogRotation
            }
        }

        # Écrire le message
        Add-Content -Path $logFilePath -Value $logMessage -Encoding UTF8 -ErrorAction Stop

        # Afficher aussi dans la console si DEBUG ou en mode verbose
        if ($Level -in @('WARNING', 'ERROR', 'CRITICAL') -or $script:LogLevel -eq 'DEBUG') {
            switch ($Level) {
                'DEBUG' { Write-Verbose $logMessage }
                'INFO' { Write-Verbose $logMessage }
                'WARNING' { Write-Warning $Message }
                'ERROR' { Write-Error $Message }
                'CRITICAL' { Write-Error "CRITICAL: $Message" }
            }
        }
    }
    catch {
        Write-Warning "Impossible d'écrire dans le fichier de log: $_"
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Effectue la rotation du fichier de log actuel.
    #>
    [CmdletBinding()]
    param()

    $logFilePath = Join-Path $script:LogPath $script:LogFileName

    if (-not (Test-Path $logFilePath)) {
        return
    }

    try {
        # Générer le nom du fichier rotaté avec timestamp
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:LogFileName)
        $extension = [System.IO.Path]::GetExtension($script:LogFileName)
        $rotatedName = "${baseName}_${timestamp}${extension}"
        $rotatedPath = Join-Path $script:LogPath $rotatedName

        # Renommer le fichier actuel
        Move-Item -Path $logFilePath -Destination $rotatedPath -Force

        Write-Verbose "Log rotaté vers: $rotatedPath"
    }
    catch {
        Write-Warning "Erreur lors de la rotation du log: $_"
    }
}

function Remove-OldLogs {
    <#
    .SYNOPSIS
        Supprime les fichiers de log plus anciens que la période de rétention.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:LogPath)) {
        return
    }

    try {
        $cutoffDate = (Get-Date).AddDays(-$script:LogRetentionDays)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:LogFileName)
        $extension = [System.IO.Path]::GetExtension($script:LogFileName)

        # Trouver les fichiers de log rotatés (pattern: basename_timestamp.extension)
        $logPattern = "${baseName}_*${extension}"
        $oldLogs = Get-ChildItem -Path $script:LogPath -Filter $logPattern -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate }

        foreach ($oldLog in $oldLogs) {
            Remove-Item -Path $oldLog.FullName -Force
            Write-Verbose "Ancien log supprimé: $($oldLog.Name)"
        }

        if ($oldLogs.Count -gt 0) {
            Write-Verbose "$($oldLogs.Count) ancien(s) log(s) supprimé(s)."
        }
    }
    catch {
        Write-Warning "Erreur lors du nettoyage des anciens logs: $_"
    }
}

function Write-DebugLog {
    <#
    .SYNOPSIS
        Raccourci pour écrire un log de niveau DEBUG.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = ''
    )

    Write-Log -Level 'DEBUG' -Message $Message -Category $Category
}

function Write-InfoLog {
    <#
    .SYNOPSIS
        Raccourci pour écrire un log de niveau INFO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = ''
    )

    Write-Log -Level 'INFO' -Message $Message -Category $Category
}

function Write-WarningLog {
    <#
    .SYNOPSIS
        Raccourci pour écrire un log de niveau WARNING.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = ''
    )

    Write-Log -Level 'WARNING' -Message $Message -Category $Category
}

function Write-ErrorLog {
    <#
    .SYNOPSIS
        Raccourci pour écrire un log de niveau ERROR.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = '',

        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception = $null
    )

    Write-Log -Level 'ERROR' -Message $Message -Category $Category -Exception $Exception
}

function Write-CriticalLog {
    <#
    .SYNOPSIS
        Raccourci pour écrire un log de niveau CRITICAL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Category = '',

        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception = $null
    )

    Write-Log -Level 'CRITICAL' -Message $Message -Category $Category -Exception $Exception
}

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Retourne le chemin complet du fichier de log actuel.
    #>
    [CmdletBinding()]
    param()

    return Join-Path $script:LogPath $script:LogFileName
}

function Get-RecentLogs {
    <#
    .SYNOPSIS
        Retourne les dernières lignes du fichier de log.

    .PARAMETER LineCount
        Nombre de lignes à retourner (défaut: 50).

    .PARAMETER Level
        Filtrer par niveau de log (optionnel).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LineCount = 50,

        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', '')]
        [string]$Level = ''
    )

    $logFilePath = Join-Path $script:LogPath $script:LogFileName

    if (-not (Test-Path $logFilePath)) {
        return @()
    }

    $logs = Get-Content -Path $logFilePath -Tail $LineCount -Encoding UTF8

    if ($Level) {
        $logs = $logs | Where-Object { $_ -match "\[$Level\]" }
    }

    return $logs
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Initialize-Logger',
    'Write-Log',
    'Write-DebugLog',
    'Write-InfoLog',
    'Write-WarningLog',
    'Write-ErrorLog',
    'Write-CriticalLog',
    'Get-LogFilePath',
    'Get-RecentLogs',
    'Invoke-LogRotation',
    'Remove-OldLogs'
)
