#Requires -Version 5.1
<#
.SYNOPSIS
    Collecteur de métriques réseau pour DEX Collector.

.DESCRIPTION
    Collecte les métriques réseau : connectivité internet, latence gateway,
    résolution DNS, connexions actives et signal WiFi.

.NOTES
    Version: 1.0.0
    Author: DEX Monitoring Team
#>

function Get-InternetConnectivity {
    <#
    .SYNOPSIS
        Teste la connectivité internet.

    .OUTPUTS
        PSCustomObject avec les métriques de connectivité.
    #>
    [CmdletBinding()]
    param()

    try {
        # Liste de serveurs à tester
        $testHosts = @(
            @{ Name = 'Google DNS'; Host = '8.8.8.8' },
            @{ Name = 'Cloudflare DNS'; Host = '1.1.1.1' },
            @{ Name = 'Microsoft'; Host = 'www.microsoft.com' }
        )

        $results = @()
        $isConnected = $false

        foreach ($test in $testHosts) {
            $pingResult = Test-Connection -ComputerName $test.Host -Count 2 -Quiet -ErrorAction SilentlyContinue

            if ($pingResult) {
                $isConnected = $true
                $latencyTest = Test-Connection -ComputerName $test.Host -Count 3 -ErrorAction SilentlyContinue
                $avgLatency = if ($latencyTest) {
                    [math]::Round(($latencyTest | Measure-Object -Property ResponseTime -Average).Average, 2)
                } else { 0 }

                $results += @{
                    target = $test.Name
                    host = $test.Host
                    reachable = $true
                    latency_ms = $avgLatency
                }
            }
            else {
                $results += @{
                    target = $test.Name
                    host = $test.Host
                    reachable = $false
                    latency_ms = 0
                }
            }
        }

        return [PSCustomObject]@{
            MetricName = 'InternetConnectivity'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                internet_connected = $isConnected
                tests_passed = ($results | Where-Object { $_.reachable }).Count
                tests_total = $results.Count
                test_results = $results
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'InternetConnectivity'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{
                internet_connected = $false
            }
        }
    }
}

function Get-GatewayLatency {
    <#
    .SYNOPSIS
        Mesure la latence vers la gateway par défaut.

    .OUTPUTS
        PSCustomObject avec les métriques de latence gateway.
    #>
    [CmdletBinding()]
    param()

    try {
        # Obtenir la gateway par défaut
        $gateway = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -and $_.DefaultIPGateway } |
            Select-Object -First 1 -ExpandProperty DefaultIPGateway

        if (-not $gateway) {
            return [PSCustomObject]@{
                MetricName = 'GatewayLatency'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    gateway_address = $null
                    gateway_reachable = $false
                    latency_ms = 0
                    message = 'Aucune gateway par défaut trouvée'
                }
            }
        }

        $gatewayAddress = $gateway[0]

        # Tester la latence vers la gateway
        $pingResults = Test-Connection -ComputerName $gatewayAddress -Count 5 -ErrorAction SilentlyContinue

        if ($pingResults) {
            $stats = $pingResults | Measure-Object -Property ResponseTime -Average -Minimum -Maximum

            return [PSCustomObject]@{
                MetricName = 'GatewayLatency'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    gateway_address = $gatewayAddress
                    gateway_reachable = $true
                    latency_avg_ms = [math]::Round($stats.Average, 2)
                    latency_min_ms = $stats.Minimum
                    latency_max_ms = $stats.Maximum
                    packets_sent = 5
                    packets_received = $pingResults.Count
                    packet_loss_percent = [math]::Round((5 - $pingResults.Count) / 5 * 100, 2)
                }
            }
        }
        else {
            return [PSCustomObject]@{
                MetricName = 'GatewayLatency'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    gateway_address = $gatewayAddress
                    gateway_reachable = $false
                    latency_avg_ms = 0
                    packet_loss_percent = 100
                }
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'GatewayLatency'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-DNSResolution {
    <#
    .SYNOPSIS
        Teste les performances de résolution DNS.

    .OUTPUTS
        PSCustomObject avec les métriques DNS.
    #>
    [CmdletBinding()]
    param()

    try {
        $testDomains = @('www.google.com', 'www.microsoft.com', 'www.cloudflare.com')
        $results = @()

        foreach ($domain in $testDomains) {
            $startTime = Get-Date

            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($domain)
                $endTime = Get-Date
                $resolutionTime = [math]::Round(($endTime - $startTime).TotalMilliseconds, 2)

                $results += @{
                    domain = $domain
                    resolved = $true
                    resolution_time_ms = $resolutionTime
                    ip_addresses = ($resolved | ForEach-Object { $_.IPAddressToString }) -join ', '
                }
            }
            catch {
                $results += @{
                    domain = $domain
                    resolved = $false
                    resolution_time_ms = 0
                    error = $_.Exception.Message
                }
            }
        }

        # Obtenir les serveurs DNS configurés
        $dnsServers = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder } |
            Select-Object -ExpandProperty DNSServerSearchOrder -ErrorAction SilentlyContinue

        $successfulResolutions = ($results | Where-Object { $_.resolved }).Count
        $avgResolutionTime = if ($successfulResolutions -gt 0) {
            [math]::Round(($results | Where-Object { $_.resolved } | Measure-Object -Property resolution_time_ms -Average).Average, 2)
        } else { 0 }

        return [PSCustomObject]@{
            MetricName = 'DNSResolution'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                dns_servers = if ($dnsServers) { $dnsServers -join ', ' } else { 'Non configuré' }
                tests_passed = $successfulResolutions
                tests_total = $testDomains.Count
                avg_resolution_time_ms = $avgResolutionTime
                dns_functional = ($successfulResolutions -gt 0)
                test_results = $results
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'DNSResolution'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-ActiveConnections {
    <#
    .SYNOPSIS
        Collecte les connexions réseau actives.

    .OUTPUTS
        PSCustomObject avec les métriques de connexions.
    #>
    [CmdletBinding()]
    param()

    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop

        # Grouper par état
        $byState = $connections | Group-Object -Property State

        # Statistiques par état
        $stateStats = @{}
        foreach ($group in $byState) {
            $stateStats[$group.Name] = $group.Count
        }

        # Top processus par nombre de connexions
        $byProcess = $connections | Group-Object -Property OwningProcess | Sort-Object Count -Descending | Select-Object -First 10
        $topProcesses = @()

        foreach ($proc in $byProcess) {
            $processInfo = Get-Process -Id $proc.Name -ErrorAction SilentlyContinue
            $topProcesses += @{
                process_id = [int]$proc.Name
                process_name = if ($processInfo) { $processInfo.ProcessName } else { 'Unknown' }
                connection_count = $proc.Count
            }
        }

        return [PSCustomObject]@{
            MetricName = 'ActiveConnections'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                total_connections = $connections.Count
                established = if ($stateStats['Established']) { $stateStats['Established'] } else { 0 }
                listen = if ($stateStats['Listen']) { $stateStats['Listen'] } else { 0 }
                time_wait = if ($stateStats['TimeWait']) { $stateStats['TimeWait'] } else { 0 }
                close_wait = if ($stateStats['CloseWait']) { $stateStats['CloseWait'] } else { 0 }
                state_breakdown = $stateStats
                top_processes = $topProcesses
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'ActiveConnections'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-WiFiSignalStrength {
    <#
    .SYNOPSIS
        Collecte la force du signal WiFi.

    .OUTPUTS
        PSCustomObject avec les métriques WiFi.
    #>
    [CmdletBinding()]
    param()

    try {
        # Vérifier si une interface WiFi est présente
        $wifiAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN' -and $_.Status -eq 'Up' } |
            Select-Object -First 1

        if (-not $wifiAdapter) {
            return [PSCustomObject]@{
                MetricName = 'WiFiSignalStrength'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    wifi_connected = $false
                    message = 'Aucun adaptateur WiFi actif trouvé'
                }
            }
        }

        # Utiliser netsh pour obtenir les informations WiFi
        $wifiInfo = netsh wlan show interfaces 2>$null

        if (-not $wifiInfo -or $wifiInfo -match 'no wireless interface') {
            return [PSCustomObject]@{
                MetricName = 'WiFiSignalStrength'
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $true
                Data = @{
                    wifi_connected = $false
                    adapter_name = $wifiAdapter.Name
                    message = 'WiFi non connecté'
                }
            }
        }

        # Parser les informations
        $ssid = ($wifiInfo | Select-String -Pattern 'SSID\s+:\s+(.+)' | Select-Object -First 1).Matches.Groups[1].Value.Trim()
        $signalMatch = ($wifiInfo | Select-String -Pattern 'Signal\s+:\s+(\d+)%').Matches
        $signal = if ($signalMatch) { [int]$signalMatch.Groups[1].Value } else { 0 }
        $radioType = ($wifiInfo | Select-String -Pattern 'Radio type\s+:\s+(.+)').Matches.Groups[1].Value.Trim()
        $channel = ($wifiInfo | Select-String -Pattern 'Channel\s+:\s+(\d+)').Matches.Groups[1].Value
        $rxRate = ($wifiInfo | Select-String -Pattern 'Receive rate \(Mbps\)\s+:\s+([\d.]+)').Matches.Groups[1].Value
        $txRate = ($wifiInfo | Select-String -Pattern 'Transmit rate \(Mbps\)\s+:\s+([\d.]+)').Matches.Groups[1].Value

        # Évaluer la qualité du signal
        $signalQuality = switch ($signal) {
            { $_ -ge 80 } { 'Excellent' }
            { $_ -ge 60 } { 'Good' }
            { $_ -ge 40 } { 'Fair' }
            { $_ -ge 20 } { 'Poor' }
            default { 'Very Poor' }
        }

        return [PSCustomObject]@{
            MetricName = 'WiFiSignalStrength'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                wifi_connected = $true
                adapter_name = $wifiAdapter.Name
                ssid = $ssid
                signal_percent = $signal
                signal_quality = $signalQuality
                radio_type = $radioType
                channel = if ($channel) { [int]$channel } else { 0 }
                receive_rate_mbps = if ($rxRate) { [double]$rxRate } else { 0 }
                transmit_rate_mbps = if ($txRate) { [double]$txRate } else { 0 }
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'WiFiSignalStrength'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Get-NetworkAdapterInfo {
    <#
    .SYNOPSIS
        Collecte les informations des adaptateurs réseau.

    .OUTPUTS
        PSCustomObject avec les informations adaptateurs.
    #>
    [CmdletBinding()]
    param()

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled }

        $adapterInfo = @()

        foreach ($adapter in $adapters) {
            $netAdapter = Get-NetAdapter -InterfaceIndex $adapter.Index -ErrorAction SilentlyContinue

            $adapterInfo += @{
                name = $adapter.Description
                mac_address = $adapter.MACAddress
                ip_addresses = $adapter.IPAddress -join ', '
                subnet_masks = $adapter.IPSubnet -join ', '
                default_gateway = if ($adapter.DefaultIPGateway) { $adapter.DefaultIPGateway -join ', ' } else { '' }
                dns_servers = if ($adapter.DNSServerSearchOrder) { $adapter.DNSServerSearchOrder -join ', ' } else { '' }
                dhcp_enabled = $adapter.DHCPEnabled
                link_speed_mbps = if ($netAdapter) { [math]::Round($netAdapter.LinkSpeed / 1000000, 0) } else { 0 }
                status = if ($netAdapter) { $netAdapter.Status } else { 'Unknown' }
            }
        }

        # Adaptateur principal (première IP ou gateway)
        $primary = $adapterInfo | Where-Object { $_.default_gateway } | Select-Object -First 1

        return [PSCustomObject]@{
            MetricName = 'NetworkAdapterInfo'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $true
            Data = @{
                adapter_count = $adapterInfo.Count
                primary_adapter = if ($primary) { $primary.name } else { '' }
                primary_ip = if ($primary) { ($primary.ip_addresses -split ', ')[0] } else { '' }
                primary_gateway = if ($primary) { ($primary.default_gateway -split ', ')[0] } else { '' }
                adapters = $adapterInfo
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            MetricName = 'NetworkAdapterInfo'
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            Success = $false
            Error = $_.Exception.Message
            Data = @{}
        }
    }
}

function Invoke-NetworkMetricCollection {
    <#
    .SYNOPSIS
        Collecte une métrique réseau spécifique par nom.

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
        'InternetConnectivity' { return Get-InternetConnectivity }
        'GatewayLatency' { return Get-GatewayLatency }
        'DNSResolution' { return Get-DNSResolution }
        'ActiveConnections' { return Get-ActiveConnections }
        'WiFiSignalStrength' { return Get-WiFiSignalStrength }
        'NetworkAdapterInfo' { return Get-NetworkAdapterInfo }
        default {
            return [PSCustomObject]@{
                MetricName = $MetricName
                Timestamp = (Get-Date).ToUniversalTime().ToString('o')
                Success = $false
                Error = "Métrique réseau inconnue: $MetricName"
                Data = @{}
            }
        }
    }
}

# Export des fonctions du module
Export-ModuleMember -Function @(
    'Get-InternetConnectivity',
    'Get-GatewayLatency',
    'Get-DNSResolution',
    'Get-ActiveConnections',
    'Get-WiFiSignalStrength',
    'Get-NetworkAdapterInfo',
    'Invoke-NetworkMetricCollection'
)
