# DEX Monitoring - Alternative Open Source à Nexthink

Système de monitoring de l'expérience utilisateur digital (DEX) basé sur PowerShell côté client avec remontée JSON vers une stack ELK (Elasticsearch, Logstash, Kibana).

## Vue d'ensemble

DEX Monitoring permet de collecter des métriques d'expérience utilisateur depuis les endpoints Windows et de les centraliser pour analyse et visualisation.

### Caractéristiques principales

- **Agent léger** : Script PowerShell natif Windows (< 5% CPU)
- **Configuration flexible** : Fichiers INI simples et lisibles
- **Hot reload** : Modification de configuration sans redémarrage
- **Buffer local** : Aucune perte de données si serveur indisponible
- **Profils** : Configurations adaptées (desktop, laptop, server)
- **Open Source** : Alternative gratuite à Nexthink

## Architecture

```
Endpoint Windows                         Serveur
┌─────────────────┐                  ┌─────────────────┐
│  DEX Collector  │ ──── JSON ────> │    Logstash     │
│   (PowerShell)  │     (HTTPS)     │                 │
└─────────────────┘                  └────────┬────────┘
                                              │
                                     ┌────────▼────────┐
                                     │  Elasticsearch  │
                                     │                 │
                                     └────────┬────────┘
                                              │
                                     ┌────────▼────────┐
                                     │     Kibana      │
                                     │  (Dashboards)   │
                                     └─────────────────┘
```

## Démarrage rapide

### 1. Installation du client

```powershell
# Copier le dossier client sur l'endpoint
Copy-Item -Path .\client -Destination C:\ProgramData\DEXCollector -Recurse

# Configurer
cd C:\ProgramData\DEXCollector
notepad config\collector.ini  # Configurer l'endpoint Logstash
notepad config\metrics.ini    # Activer les métriques souhaitées
```

### 2. Test du collecteur

```powershell
# Mode test (pas d'envoi vers Logstash)
.\DEXCollector.ps1 -RunOnce -TestMode

# Voir le JSON généré dans:
# C:\ProgramData\DEXCollector\export\
```

### 3. Exécution

```powershell
# Mode continu
.\DEXCollector.ps1

# Ou créer une tâche planifiée (recommandé)
```

## Métriques collectées

### Système
- CPU (utilisation, cores)
- Mémoire (RAM, virtuelle)
- Disque (espace, I/O)
- Uptime

### Réseau
- Connectivité Internet
- Latence gateway
- Résolution DNS
- Signal WiFi

### Sécurité
- Status Antivirus
- Status Firewall
- Windows Update
- BitLocker

### Applications
- Processus en cours
- Top consommateurs CPU/RAM
- Crashes applicatifs

## Configuration

### metrics.ini

```ini
[System]
CPUUsage = true, 5, high      # Activé, toutes les 5 min, priorité haute
MemoryUsage = true, 5, high
DiskSpace = true, 15, medium  # Toutes les 15 min

[Security]
AntivirusStatus = true, 30, high
```

### collector.ini

```ini
[Logstash]
Endpoint = https://logstash.example.com:5044
UseAuthentication = true

[Buffer]
EnableBuffer = true
BufferPath = C:\ProgramData\DEXCollector\buffer
```

## Profils disponibles

| Profil | Description |
|--------|-------------|
| desktop | Configuration standard |
| laptop | Économie batterie, WiFi monitoring |
| server | Monitoring intensif, haute fréquence |

## Structure du projet

```
dex_monitoring/
├── client/                    # Agent de collecte
│   ├── DEXCollector.ps1       # Script principal
│   ├── config/                # Configuration
│   │   ├── metrics.ini
│   │   ├── collector.ini
│   │   └── profiles/
│   ├── modules/               # Modules PowerShell
│   └── collectors/            # Collecteurs spécialisés
├── server/                    # Stack ELK (à venir)
└── README.md
```

## Compatibilité

- Windows 10 / 11
- Windows Server 2016+
- PowerShell 5.1+

## Licence

MIT License

## Contribution

Les contributions sont les bienvenues ! Voir CONTRIBUTING.md.
