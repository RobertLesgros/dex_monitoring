#Requires -Version 5.1
<#
.SYNOPSIS
    Collecteur de métriques de sécurité pour DEX Collector.

.DESCRIPTION
    Collecte les métriques de sécurité : antivirus, firewall, Windows Update,
    BitLocker et état général de la sécurité du système.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

function Get-AntivirusStatus {
    <#
    .SYNOPSIS
        Collecte l'état de l'antivirus installé.

    .OUTPUTS
        PSCustomObject avec les métriques antivirus.
    #>
    [CmdletBinding()]
    param()

    try {
        # Windows Security Center (fonctionne sur Windows 10/11)
        $antivirusProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop

        if (-not $antivirusProducts) {
            return [PSCustomObject]@{
                MetricName = 'AntivirusStatus'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    antivirus_installed = $false
                    message = 'Aucun antivirus détecté via Security Center'
                }
            }
        }

        $avInfo = @()

        foreach ($av in $antivirusProducts) {
            # Décoder le productState pour obtenir l'état
            $productState = $av.productState
            $hexState = [Convert]::ToString($productState, 16).PadLeft(6, '0')

            # Les 2 premiers caractères indiquent le type de produit
            # Les 2 suivants indiquent l'état des définitions
            # Les 2 derniers indiquent l'état du produit

            $defStatus = [int]("0x" + $hexState.Substring(2, 2))
            $rtpStatus = [int]("0x" + $hexState.Substring(4, 2))

            $definitionsUpToDate = ($defStatus -band 0x10) -eq 0
            $realTimeProtectionEnabled = ($rtpStatus -band 0x10) -ne 0

            $avInfo += @{
                display_name = $av.displayName
                instance_guid = $av.instanceGuid
                path_to_signed_product_exe = $av.pathToSignedProductExe
                product_state = $productState
                definitions_up_to_date = $definitionsUpToDate
                real_time_protection = $realTimeProtectionEnabled
            }
        }

        # Vérifier aussi Windows Defender spécifiquement
        $defenderStatus = $null
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        }
        catch {
            # Windows Defender peut ne pas être disponible
        }

        $defenderInfo = @{}
        if ($defenderStatus) {
            $defenderInfo = @{
                defender_enabled = $defenderStatus.AntivirusEnabled
                real_time_protection = $defenderStatus.RealTimeProtectionEnabled
                behavior_monitor = $defenderStatus.BehaviorMonitorEnabled
                antispyware_enabled = $defenderStatus.AntispywareEnabled
                on_access_protection = $defenderStatus.OnAccessProtectionEnabled
                ioav_protection = $defenderStatus.IoavProtectionEnabled
                definitions_age_days = $defenderStatus.AntivirusSignatureAge
                last_quick_scan = if ($defenderStatus.QuickScanEndTime) { $defenderStatus.QuickScanEndTime.ToString('o') } else { $null }
                last_full_scan = if ($defenderStatus.FullScanEndTime) { $defenderStatus.FullScanEndTime.ToString('o') } else { $null }
            }
        }

        # Déterminer l'état global
        $primaryAV = $avInfo | Where-Object { $_.real_time_protection } | Select-Object -First 1
        if (-not $primaryAV) {
            $primaryAV = $avInfo | Select-Object -First 1
        }

        return [PSCustomObject]@{
            MetricName = 'AntivirusStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                antivirus_installed = $true
                antivirus_count = $avInfo.Count
                primary_antivirus = if ($primaryAV) { $primaryAV.display_name } else { 'Unknown' }
                antivirus_enabled = if ($primaryAV) { $primaryAV.real_time_protection } else { $false }
                definitions_updated = if ($primaryAV) { $primaryAV.definitions_up_to_date } else { $false }
                antivirus_products = $avInfo
                windows_defender = $defenderInfo
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'AntivirusStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{
                antivirus_installed = $false
            }
        }
    }
}

function Get-FirewallStatus {
    <#
    .SYNOPSIS
        Collecte l'état du pare-feu Windows.

    .OUTPUTS
        PSCustomObject avec les métriques firewall.
    #>
    [CmdletBinding()]
    param()

    try {
        # Obtenir l'état du firewall pour tous les profils
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

        $profileStatus = @{}
        $allEnabled = $true

        foreach ($profile in $firewallProfiles) {
            $profileStatus[$profile.Name] = @{
                enabled = $profile.Enabled
                default_inbound_action = $profile.DefaultInboundAction.ToString()
                default_outbound_action = $profile.DefaultOutboundAction.ToString()
                allow_inbound_rules = $profile.AllowInboundRules
                allow_local_firewall_rules = $profile.AllowLocalFirewallRules
                log_allowed = $profile.LogAllowed
                log_blocked = $profile.LogBlocked
                log_file_path = $profile.LogFileName
            }

            if (-not $profile.Enabled) {
                $allEnabled = $false
            }
        }

        # Compter les règles
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        $enabledRules = ($rules | Where-Object { $_.Enabled -eq 'True' }).Count
        $inboundRules = ($rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }).Count
        $outboundRules = ($rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled -eq 'True' }).Count

        return [PSCustomObject]@{
            MetricName = 'FirewallStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                firewall_enabled = $allEnabled
                all_profiles_enabled = $allEnabled
                profiles = $profileStatus
                total_rules = if ($rules) { $rules.Count } else { 0 }
                enabled_rules = $enabledRules
                inbound_rules = $inboundRules
                outbound_rules = $outboundRules
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'FirewallStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{
                firewall_enabled = $false
            }
        }
    }
}

function Get-WindowsUpdateStatus {
    <#
    .SYNOPSIS
        Collecte l'état des mises à jour Windows.

    .OUTPUTS
        PSCustomObject avec les métriques Windows Update.
    #>
    [CmdletBinding()]
    param()

    try {
        # Informations sur la dernière mise à jour installée
        $lastUpdate = Get-HotFix -ErrorAction SilentlyContinue |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1

        # Obtenir les informations du service Windows Update
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

        # Vérifier les mises à jour en attente via COM (méthode standard)
        $pendingUpdates = @()
        $updateCount = 0

        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()

            # Rechercher les mises à jour non installées (peut prendre du temps)
            # On limite la recherche aux mises à jour critiques pour la performance
            $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")

            $updateCount = $searchResult.Updates.Count

            foreach ($update in $searchResult.Updates) {
                if ($pendingUpdates.Count -lt 10) {
                    # Limiter à 10 pour la performance
                    $pendingUpdates += @{
                        title = $update.Title
                        kb_article_ids = ($update.KBArticleIDs -join ', ')
                        severity = if ($update.MsrcSeverity) { $update.MsrcSeverity } else { 'Not Rated' }
                        is_mandatory = $update.IsMandatory
                        is_downloaded = $update.IsDownloaded
                        size_mb = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                    }
                }
            }
        }
        catch {
            # COM peut échouer, continuer sans les mises à jour en attente
        }

        # Calculer le nombre de jours depuis la dernière mise à jour
        $daysSinceLastUpdate = if ($lastUpdate -and $lastUpdate.InstalledOn) {
            [math]::Floor(((Get-Date) - $lastUpdate.InstalledOn).TotalDays)
        } else { -1 }

        # Déterminer le statut global
        $updateStatus = 'Unknown'
        if ($daysSinceLastUpdate -ge 0) {
            $updateStatus = switch ($daysSinceLastUpdate) {
                { $_ -le 7 } { 'Current' }
                { $_ -le 30 } { 'Slightly Behind' }
                { $_ -le 60 } { 'Behind' }
                default { 'Critically Behind' }
            }
        }

        return [PSCustomObject]@{
            MetricName = 'WindowsUpdateStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                last_update_date = if ($lastUpdate -and $lastUpdate.InstalledOn) { $lastUpdate.InstalledOn.ToString('o') } else { $null }
                last_update_kb = if ($lastUpdate) { $lastUpdate.HotFixID } else { '' }
                days_since_last_update = $daysSinceLastUpdate
                update_status = $updateStatus
                pending_update_count = $updateCount
                pending_updates = $pendingUpdates
                wu_service_status = if ($wuService) { $wuService.Status.ToString() } else { 'Unknown' }
                wu_service_running = if ($wuService) { $wuService.Status -eq 'Running' } else { $false }
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'WindowsUpdateStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-BitLockerStatus {
    <#
    .SYNOPSIS
        Collecte l'état de BitLocker sur les volumes.

    .OUTPUTS
        PSCustomObject avec les métriques BitLocker.
    #>
    [CmdletBinding()]
    param()

    try {
        # Vérifier si BitLocker est disponible
        $bitlockerModule = Get-Module -ListAvailable -Name BitLocker -ErrorAction SilentlyContinue

        if (-not $bitlockerModule) {
            return [PSCustomObject]@{
                MetricName = 'BitLockerStatus'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    bitlocker_available = $false
                    message = 'Module BitLocker non disponible'
                }
            }
        }

        $volumes = Get-BitLockerVolume -ErrorAction Stop
        $volumeStatus = @()
        $systemDriveProtected = $false

        foreach ($volume in $volumes) {
            $isSystemDrive = $volume.MountPoint -eq $env:SystemDrive + '\'

            $volumeStatus += @{
                mount_point = $volume.MountPoint
                volume_type = $volume.VolumeType.ToString()
                protection_status = $volume.ProtectionStatus.ToString()
                volume_status = $volume.VolumeStatus.ToString()
                encryption_percentage = $volume.EncryptionPercentage
                encryption_method = if ($volume.EncryptionMethod) { $volume.EncryptionMethod.ToString() } else { 'None' }
                key_protector_types = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ', '
                is_system_drive = $isSystemDrive
            }

            if ($isSystemDrive -and $volume.ProtectionStatus -eq 'On') {
                $systemDriveProtected = $true
            }
        }

        return [PSCustomObject]@{
            MetricName = 'BitLockerStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                bitlocker_available = $true
                system_drive_protected = $systemDriveProtected
                protected_volumes = ($volumeStatus | Where-Object { $_.protection_status -eq 'On' }).Count
                total_volumes = $volumeStatus.Count
                volumes = $volumeStatus
            }
        }
    }
    catch {
        # BitLocker peut nécessiter des privilèges admin
        return [PSCustomObject]@{
            MetricName = 'BitLockerStatus'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{
                bitlocker_available = $false
                message = 'Impossible de vérifier BitLocker (privilèges admin requis)'
            }
        }
    }
}

function Get-PendingUpdates {
    <#
    .SYNOPSIS
        Collecte les mises à jour en attente de manière détaillée.

    .OUTPUTS
        PSCustomObject avec les mises à jour en attente.
    #>
    [CmdletBinding()]
    param()

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Rechercher les mises à jour non installées
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")

        $updates = @()
        $criticalCount = 0
        $importantCount = 0
        $totalSizeMB = 0

        foreach ($update in $searchResult.Updates) {
            $severity = if ($update.MsrcSeverity) { $update.MsrcSeverity } else { 'Unrated' }

            switch ($severity) {
                'Critical' { $criticalCount++ }
                'Important' { $importantCount++ }
            }

            $sizeMB = [math]::Round($update.MaxDownloadSize / 1MB, 2)
            $totalSizeMB += $sizeMB

            $updates += @{
                title = $update.Title
                description = if ($update.Description.Length -gt 200) {
                    $update.Description.Substring(0, 200) + '...'
                } else { $update.Description }
                kb_article_ids = ($update.KBArticleIDs -join ', ')
                severity = $severity
                categories = ($update.Categories | ForEach-Object { $_.Name }) -join ', '
                is_mandatory = $update.IsMandatory
                is_downloaded = $update.IsDownloaded
                reboot_required = $update.RebootRequired
                size_mb = $sizeMB
            }
        }

        return [PSCustomObject]@{
            MetricName = 'PendingUpdates'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                total_pending = $searchResult.Updates.Count
                critical_count = $criticalCount
                important_count = $importantCount
                total_size_mb = [math]::Round($totalSizeMB, 2)
                updates = $updates
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'PendingUpdates'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-SecuritySummary {
    <#
    .SYNOPSIS
        Génère un résumé de l'état de sécurité global.

    .OUTPUTS
        PSCustomObject avec le résumé de sécurité.
    #>
    [CmdletBinding()]
    param()

    try {
        # Collecter les métriques individuelles
        $av = Get-AntivirusStatus
        $fw = Get-FirewallStatus
        $wu = Get-WindowsUpdateStatus

        # Calculer un score de sécurité simple (0-100)
        $score = 100
        $issues = @()

        # Antivirus
        if (-not $av.Data.antivirus_installed) {
            $score -= 30
            $issues += 'Aucun antivirus installé'
        }
        elseif (-not $av.Data.antivirus_enabled) {
            $score -= 20
            $issues += 'Antivirus désactivé'
        }
        elseif (-not $av.Data.definitions_updated) {
            $score -= 10
            $issues += 'Définitions antivirus obsolètes'
        }

        # Firewall
        if (-not $fw.Data.firewall_enabled) {
            $score -= 20
            $issues += 'Pare-feu désactivé'
        }
        elseif (-not $fw.Data.all_profiles_enabled) {
            $score -= 10
            $issues += 'Certains profils de pare-feu sont désactivés'
        }

        # Windows Update
        if ($wu.Data.days_since_last_update -gt 60) {
            $score -= 20
            $issues += 'Mises à jour Windows très en retard (> 60 jours)'
        }
        elseif ($wu.Data.days_since_last_update -gt 30) {
            $score -= 10
            $issues += 'Mises à jour Windows en retard (> 30 jours)'
        }

        # Déterminer le niveau de risque
        $riskLevel = switch ($score) {
            { $_ -ge 90 } { 'Low' }
            { $_ -ge 70 } { 'Medium' }
            { $_ -ge 50 } { 'High' }
            default { 'Critical' }
        }

        return [PSCustomObject]@{
            MetricName = 'SecuritySummary'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                security_score = [math]::Max(0, $score)
                risk_level = $riskLevel
                issues_count = $issues.Count
                issues = $issues
                antivirus_ok = $av.Data.antivirus_installed -and $av.Data.antivirus_enabled
                firewall_ok = $fw.Data.firewall_enabled
                updates_ok = $wu.Data.days_since_last_update -le 30
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'SecuritySummary'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Invoke-SecurityMetricCollection {
    <#
    .SYNOPSIS
        Collecte une métrique de sécurité spécifique par nom.

    .PARAMETER MetricName
        Nom de la métrique à collecter.

    .OUTPUTS
        Résultat de la collecte.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MetricName
    )

    switch ($MetricName) {
        'AntivirusStatus' { return Get-AntivirusStatus }
        'FirewallStatus' { return Get-FirewallStatus }
        'WindowsUpdateStatus' { return Get-WindowsUpdateStatus }
        'BitLockerStatus' { return Get-BitLockerStatus }
        'PendingUpdates' { return Get-PendingUpdates }
        'SecuritySummary' { return Get-SecuritySummary }
        default {
            return [PSCustomObject]@{
                MetricName = $MetricName
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $false
                Error = "Métrique de sécurité inconnue: $MetricName"
                Data = @{}
            }
        }
    }
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Get-AntivirusStatus',
    'Get-FirewallStatus',
    'Get-WindowsUpdateStatus',
    'Get-BitLockerStatus',
    'Get-PendingUpdates',
    'Get-SecuritySummary',
    'Invoke-SecurityMetricCollection'
)
