#Requires -Version 5.1
<#
.SYNOPSIS
    Collecteur de métriques système pour DEX Collector.

.DESCRIPTION
    Collecte les métriques système : CPU, mémoire, disque, I/O et uptime.
    Utilise WMI/CIM pour une compatibilité maximale Windows.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

function Get-CPUUsage {
    <#
    .SYNOPSIS
        Collecte l'utilisation CPU actuelle et moyenne.

    .OUTPUTS
        PSCustomObject avec les métriques CPU.
    #>
    [CmdletBinding()]
    param()

    try {
        # Utiliser Get-CimInstance pour de meilleures performances
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop

        # Calculer la moyenne si plusieurs processeurs
        $cpuPercent = ($cpu | Measure-Object -Property LoadPercentage -Average).Average

        # Informations supplémentaires sur le CPU
        $cpuInfo = $cpu | Select-Object -First 1

        return [PSCustomObject]@{
            MetricName = 'CPUUsage'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                cpu_percent = [math]::Round($cpuPercent, 2)
                cpu_name = $cpuInfo.Name
                cpu_cores = $cpuInfo.NumberOfCores
                cpu_logical_processors = $cpuInfo.NumberOfLogicalProcessors
                cpu_max_clock_speed_mhz = $cpuInfo.MaxClockSpeed
                cpu_current_clock_speed_mhz = $cpuInfo.CurrentClockSpeed
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'CPUUsage'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-MemoryUsage {
    <#
    .SYNOPSIS
        Collecte l'utilisation de la mémoire RAM.

    .OUTPUTS
        PSCustomObject avec les métriques mémoire.
    #>
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        # Calculs mémoire
        $totalMemoryMB = [math]::Round($cs.TotalPhysicalMemory / 1MB, 2)
        $freeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1KB, 2)  # FreePhysicalMemory est en KB
        $usedMemoryMB = $totalMemoryMB - $freeMemoryMB
        $memoryPercent = [math]::Round(($usedMemoryMB / $totalMemoryMB) * 100, 2)

        # Mémoire virtuelle
        $totalVirtualMB = [math]::Round($os.TotalVirtualMemorySize / 1KB, 2)
        $freeVirtualMB = [math]::Round($os.FreeVirtualMemory / 1KB, 2)
        $usedVirtualMB = $totalVirtualMB - $freeVirtualMB

        return [PSCustomObject]@{
            MetricName = 'MemoryUsage'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                memory_percent = $memoryPercent
                memory_total_mb = $totalMemoryMB
                memory_used_mb = [math]::Round($usedMemoryMB, 2)
                memory_available_mb = [math]::Round($freeMemoryMB, 2)
                virtual_total_mb = $totalVirtualMB
                virtual_used_mb = [math]::Round($usedVirtualMB, 2)
                virtual_available_mb = $freeVirtualMB
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'MemoryUsage'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-DiskSpace {
    <#
    .SYNOPSIS
        Collecte l'espace disque pour tous les volumes.

    .OUTPUTS
        PSCustomObject avec les métriques disque.
    #>
    [CmdletBinding()]
    param()

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop

        $diskMetrics = @()

        foreach ($disk in $disks) {
            $totalGB = [math]::Round($disk.Size / 1GB, 2)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedGB = $totalGB - $freeGB
            $usedPercent = if ($totalGB -gt 0) { [math]::Round(($usedGB / $totalGB) * 100, 2) } else { 0 }

            $diskMetrics += @{
                drive_letter = $disk.DeviceID
                volume_name = $disk.VolumeName
                total_gb = $totalGB
                used_gb = $usedGB
                free_gb = $freeGB
                used_percent = $usedPercent
                file_system = $disk.FileSystem
            }
        }

        # Résumé du disque principal (généralement C:)
        $primaryDisk = $diskMetrics | Where-Object { $_.drive_letter -eq 'C:' } | Select-Object -First 1

        return [PSCustomObject]@{
            MetricName = 'DiskSpace'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                primary_drive_letter = if ($primaryDisk) { $primaryDisk.drive_letter } else { '' }
                primary_total_gb = if ($primaryDisk) { $primaryDisk.total_gb } else { 0 }
                primary_free_gb = if ($primaryDisk) { $primaryDisk.free_gb } else { 0 }
                primary_used_percent = if ($primaryDisk) { $primaryDisk.used_percent } else { 0 }
                all_disks = $diskMetrics
                disk_count = $diskMetrics.Count
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'DiskSpace'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-DiskIO {
    <#
    .SYNOPSIS
        Collecte les métriques d'I/O disque.

    .OUTPUTS
        PSCustomObject avec les métriques I/O.
    #>
    [CmdletBinding()]
    param()

    try {
        $diskPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop |
            Where-Object { $_.Name -ne '_Total' }

        $ioMetrics = @()

        foreach ($disk in $diskPerf) {
            $ioMetrics += @{
                disk_name = $disk.Name
                disk_reads_per_sec = $disk.DiskReadsPerSec
                disk_writes_per_sec = $disk.DiskWritesPerSec
                disk_read_bytes_per_sec = $disk.DiskReadBytesPerSec
                disk_write_bytes_per_sec = $disk.DiskWriteBytesPerSec
                avg_disk_queue_length = $disk.AvgDiskQueueLength
                percent_disk_time = $disk.PercentDiskTime
                percent_idle_time = $disk.PercentIdleTime
            }
        }

        # Totaux
        $total = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop |
            Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1

        return [PSCustomObject]@{
            MetricName = 'DiskIO'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                total_reads_per_sec = if ($total) { $total.DiskReadsPerSec } else { 0 }
                total_writes_per_sec = if ($total) { $total.DiskWritesPerSec } else { 0 }
                total_read_bytes_per_sec = if ($total) { $total.DiskReadBytesPerSec } else { 0 }
                total_write_bytes_per_sec = if ($total) { $total.DiskWriteBytesPerSec } else { 0 }
                avg_queue_length = if ($total) { $total.AvgDiskQueueLength } else { 0 }
                percent_busy = if ($total) { $total.PercentDiskTime } else { 0 }
                disk_details = $ioMetrics
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'DiskIO'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-SystemUptime {
    <#
    .SYNOPSIS
        Collecte l'uptime du système.

    .OUTPUTS
        PSCustomObject avec les métriques uptime.
    #>
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        $lastBootTime = $os.LastBootUpTime
        $uptime = (Get-Date) - $lastBootTime

        return [PSCustomObject]@{
            MetricName = 'SystemUptime'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                last_boot_time = $lastBootTime.ToUniversalTime().ToString('o')
                uptime_days = [math]::Floor($uptime.TotalDays)
                uptime_hours = [math]::Floor($uptime.TotalHours)
                uptime_minutes = [math]::Floor($uptime.TotalMinutes)
                uptime_seconds = [math]::Floor($uptime.TotalSeconds)
                uptime_formatted = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'SystemUptime'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Collecte les informations système de base (utilisé pour l'enrichissement).

    .OUTPUTS
        PSCustomObject avec les informations système.
    #>
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop

        return [PSCustomObject]@{
            Success = $true
            Computer = @{
                hostname = $env:COMPUTERNAME
                domain = $cs.Domain
                workgroup = $cs.Workgroup
                manufacturer = $cs.Manufacturer
                model = $cs.Model
                serial_number = $bios.SerialNumber
                bios_version = $bios.SMBIOSBIOSVersion
            }
            OperatingSystem = @{
                name = $os.Caption
                version = $os.Version
                build_number = $os.BuildNumber
                architecture = $os.OSArchitecture
                install_date = $os.InstallDate.ToUniversalTime().ToString('o')
                service_pack = $os.ServicePackMajorVersion
            }
            User = @{
                username = $env:USERNAME
                user_domain = $env:USERDOMAIN
                user_profile = $env:USERPROFILE
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
            Computer = @{}
            OperatingSystem = @{}
            User = @{}
        }
    }
}

function Invoke-SystemMetricCollection {
    <#
    .SYNOPSIS
        Collecte une métrique système spécifique par nom.

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
        'CPUUsage' { return Get-CPUUsage }
        'MemoryUsage' { return Get-MemoryUsage }
        'DiskSpace' { return Get-DiskSpace }
        'DiskIO' { return Get-DiskIO }
        'SystemUptime' { return Get-SystemUptime }
        default {
            return [PSCustomObject]@{
                MetricName = $MetricName
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $false
                Error = "Métrique système inconnue: $MetricName"
                Data = @{}
            }
        }
    }
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Get-CPUUsage',
    'Get-MemoryUsage',
    'Get-DiskSpace',
    'Get-DiskIO',
    'Get-SystemUptime',
    'Get-SystemInfo',
    'Invoke-SystemMetricCollection'
)
