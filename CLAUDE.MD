# Projet DEX Monitoring - Alternative Nexthink

## Vue d'ensemble
Système de monitoring de l'expérience utilisateur digital (DEX) basé sur PowerShell côté client avec remontée JSON vers une stack ELK (Elasticsearch, Logstash, Kibana).

## Objectifs du projet
- Collecter des métriques d'expérience utilisateur depuis les endpoints Windows
- Centraliser les données dans Elasticsearch via Logstash
- Visualiser et analyser dans Kibana
- Détecter proactivement les problèmes de performance

## Focus du projet : PARTIE CLIENTE

⚠️ **Note importante** : Ce projet se concentre **principalement sur la partie cliente (collecteur PowerShell)** car la partie serveur (stack ELK) est relativement standard et bien documentée.

## Principes d'architecture

### Architecture de configuration INI ✅
Le système utilise un fichier `.ini` pour configurer les métriques :
- Liste des métriques à collecter
- Fréquence de collecte par métrique (optimisation performance)
- Activation/désactivation via commentaire de ligne
- Recharge à chaud de la configuration (hot reload)
- Profils différents selon types de machines

**Avantages :**
- ✅ Déploiement simplifié (GPO pour pousser config)
- ✅ Maintenance facile (pas de recompilation)
- ✅ Performance optimisée (fréquences différenciées)
- ✅ Debug facilité (activer/désactiver rapidement)

## Architecture

### Composants principaux

#### 1. 🎯 Agent Client (PowerShell) - FOCUS PRINCIPAL
- Script PowerShell s'exécutant sur chaque endpoint
- Configuration via fichiers INI
- Collecte de métriques système et applicatives à fréquences variables
- Sérialisation en JSON
- Buffer local en cas d'indisponibilité serveur
- Envoi vers Logstash (HTTP/HTTPS)
- Service Windows ou Tâche planifiée

#### 2. Serveur de collecte (Logstash) - Standard
- Reception des données JSON via HTTP input
- Parsing et enrichissement
- Indexation dans Elasticsearch

#### 3. Stockage et analyse (Elasticsearch) - Standard
- Stockage des métriques temporelles
- Indexation pour recherche rapide
- Agrégations pour analytics

#### 4. Visualisation (Kibana) - Standard
- Dashboards temps réel
- Alertes et notifications
- Rapports d'analyse

## Métriques à collecter

### ✅ Validation de faisabilité PowerShell

**Résultat de l'analyse : 85-90% des métriques Nexthink sont reproductibles en PowerShell**

#### Catégories parfaitement reproductibles (90-100%)
- ✅ Métriques système (CPU, RAM, Disk, I/O)
- ✅ Métriques hardware (Model, Serial, BIOS, Battery)
- ✅ Inventaire software (apps installées, versions)
- ✅ Métriques réseau de base (connexions, latence, throughput)
- ✅ Métriques sécurité (AV, Firewall, BitLocker, Updates)
- ✅ Événements système (Event Logs)

#### Catégories partiellement reproductibles (50-80%)
- ⚠️ Métriques expérience utilisateur (boot time, login time via Event Logs)
- ⚠️ Détection hangs/freeze (heuristiques via Event Logs)
- ⚠️ Métriques réseau avancées (RTT détaillé nécessite monitoring continu)

#### Limitations (non reproductibles nativement)
- ❌ Page load time web (nécessite extension navigateur)
- ❌ Monitoring kernel-level continu (PowerShell = user-mode)
- ❌ Threat intelligence binaries (nécessite API externe type VirusTotal)
- ❌ Real-time monitoring < 1 minute (fréquence recommandée : 5 min)

**Conclusion : PowerShell est largement suffisant pour 85-90% des cas d'usage Nexthink**

### Métriques Système
- [ ] CPU (utilisation moyenne, pics)
- [ ] Mémoire (RAM utilisée, disponible, paging)
- [ ] Disque (espace, I/O, fragmentation)
- [ ] Réseau (latence, bande passante, connectivité)
- [ ] Uptime système
- [ ] Événements Windows critiques

### Métriques Applications
- [ ] Applications installées et versions
- [ ] Temps de démarrage des applications
- [ ] Crashes et erreurs applicatives
- [ ] Utilisation ressources par application
- [ ] Applications non-répondantes

### Métriques Expérience Utilisateur
- [ ] Temps de boot
- [ ] Temps de login
- [ ] Lenteurs perçues
- [ ] Freeze/hang detection
- [ ] Session crashes

### Métriques Sécurité
- [ ] Status antivirus
- [ ] Mises à jour Windows (dernière installation, patches manquants)
- [ ] Firewall status
- [ ] BitLocker status
- [ ] Ports ouverts suspects

### Métriques Business
- [ ] Utilisateur et machine info (nom, domaine, site)
- [ ] Configuration matérielle
- [ ] Modèle et constructeur
- [ ] Version OS et build

## Structure du projet

```
dex-monitoring/
├── client/                              # 🎯 FOCUS PRINCIPAL
│   ├── DEXCollector.ps1                 # Script principal (orchestrateur)
│   │
│   ├── config/                          # ⚙️ Configuration INI
│   │   ├── metrics.ini                  # Configuration des métriques et fréquences
│   │   ├── collector.ini                # Configuration générale du collecteur
│   │   ├── profiles/                    # Profils par type de machine
│   │   │   ├── metrics-server.ini       # Profil pour serveurs
│   │   │   ├── metrics-desktop.ini      # Profil pour desktops
│   │   │   └── metrics-laptop.ini       # Profil pour laptops
│   │   └── README.md                    # Documentation configuration
│   │
│   ├── modules/                         # 📦 Modules PowerShell
│   │   ├── ConfigParser.psm1            # Parse et valide fichiers INI
│   │   ├── MetricsScheduler.psm1        # Gestion des fréquences de collecte
│   │   ├── MetricsCollector.psm1        # Orchestration collecte métriques
│   │   ├── DataSender.psm1              # Envoi vers Logstash + buffer local
│   │   └── Logger.psm1                  # Logging local
│   │
│   ├── collectors/                      # 🔍 Collecteurs spécialisés par catégorie
│   │   ├── SystemMetrics.psm1           # CPU, RAM, Disk, I/O
│   │   ├── NetworkMetrics.psm1          # Réseau, latence, connectivité
│   │   ├── ApplicationMetrics.psm1      # Apps, processus, crashes
│   │   ├── SecurityMetrics.psm1         # AV, Firewall, Updates, BitLocker
│   │   ├── UserExperienceMetrics.psm1   # Boot, login, session
│   │   ├── HardwareMetrics.psm1         # Hardware info, battery
│   │   └── EventMetrics.psm1            # Event Logs Windows
│   │
│   ├── installer/                       # 📦 Installation et déploiement
│   │   ├── Install-DEXAgent.ps1         # Script d'installation
│   │   ├── Uninstall-DEXAgent.ps1       # Script de désinstallation
│   │   ├── Register-Service.ps1         # Création service Windows
│   │   └── Deploy-GPO.ps1               # Aide déploiement GPO
│   │
│   ├── tests/                           # 🧪 Tests
│   │   ├── Test-Collectors.ps1          # Tests unitaires collecteurs
│   │   ├── Test-ConfigParser.ps1        # Tests parsing INI
│   │   └── Test-EndToEnd.ps1            # Tests bout-en-bout
│   │
│   └── docs/                            # 📚 Documentation
│       ├── installation.md              # Guide installation
│       ├── configuration.md             # Guide configuration INI
│       ├── metrics-reference.md         # Référence toutes les métriques
│       └── troubleshooting.md           # Guide dépannage
│
├── server/                              # ⚙️ Configuration ELK (standard)
│   ├── logstash/
│   │   ├── pipelines/
│   │   │   └── dex-pipeline.conf        # Pipeline Logstash
│   │   └── patterns/
│   │       └── dex-patterns             # Grok patterns custom
│   ├── elasticsearch/
│   │   ├── mappings/
│   │   │   └── dex-index-template.json  # Template d'index
│   │   └── queries/
│   │       └── sample-queries.json      # Requêtes exemples
│   └── kibana/
│       ├── dashboards/
│       │   ├── overview.ndjson          # Dashboard vue générale
│       │   ├── performance.ndjson       # Dashboard performance
│       │   └── security.ndjson          # Dashboard sécurité
│       └── visualizations/
│           └── *.ndjson                 # Visualisations
│
├── docker/
│   ├── docker-compose.yml               # Stack ELK pour dev/test
│   └── .env.example                     # Variables d'environnement
│
└── README.md
```

## Architecture de configuration INI

### Format du fichier metrics.ini

Le fichier `metrics.ini` contrôle quelles métriques sont collectées et à quelle fréquence.

```ini
# Format : MetricName = Enabled, FrequencyMinutes, Priority

[System]
CPUUsage = true, 5, high              # Collecté toutes les 5 minutes
MemoryUsage = true, 5, high
DiskSpace = true, 15, medium          # Collecté toutes les 15 minutes
DiskIO = false, 10, low               # Désactivé (via false)
# SystemUptime = true, 60, low        # Désactivé (via commentaire)

[Network]
ActiveConnections = true, 5, high
GatewayLatency = true, 15, medium
WiFiSignalStrength = true, 10, medium

[Applications]
RunningProcesses = true, 10, medium
TopCPUConsumers = true, 5, high
ApplicationCrashes = true, 5, high
InstalledApplications = true, 1440, low  # Une fois par jour

[Security]
AntivirusStatus = true, 30, high
FirewallStatus = true, 30, high
WindowsUpdateStatus = true, 60, high
PendingUpdates = true, 120, medium

[UserExperience]
BootTime = true, 0, high              # 0 = event-driven (à chaque boot)
LoginTime = true, 0, high             # 0 = event-driven (à chaque login)
SessionUptime = true, 30, medium

[Hardware]
ComputerModel = true, 1440, low       # Une fois par jour (données statiques)
BatteryHealth = true, 60, medium
BatteryStatus = true, 15, medium

[Events]
SystemErrors = true, 15, high
CriticalEvents = true, 5, high
```

### Format du fichier collector.ini

Configuration générale du collecteur :

```ini
[General]
CollectorVersion = 1.0.0
LogLevel = INFO                       # DEBUG, INFO, WARNING, ERROR

[Collection]
BaseFrequency = 5                     # Fréquence de base en minutes
BufferSize = 60                       # Taille buffer local en minutes
MaxRetries = 3                        # Tentatives d'envoi

[Logstash]
Endpoint = https://logstash.example.com:5044
UseAuthentication = false
Timeout = 30

[Local]
LogPath = C:\ProgramData\DEXCollector\logs
LogRetentionDays = 7
BufferPath = C:\ProgramData\DEXCollector\buffer
MaxBufferSizeMB = 100

[Performance]
MaxCPUUsage = 5                       # Impact CPU max autorisé (%)
CollectionDelay = 100                 # Délai entre collectes (ms)
MetricTimeout = 30                    # Timeout par métrique (secondes)

[Advanced]
AutoReloadConfig = true               # Recharge auto de la config
ConfigReloadInterval = 15             # Fréquence reload (minutes)
```

### Profils par type de machine

**metrics-server.ini** : Serveurs (fréquence élevée, toutes métriques)
```ini
[System]
CPUUsage = true, 2, high              # Toutes les 2 minutes
MemoryUsage = true, 2, high
DiskIO = true, 5, high                # Plus fréquent sur serveurs
```

**metrics-desktop.ini** : Postes de travail (fréquence standard)
```ini
[System]
CPUUsage = true, 5, high
MemoryUsage = true, 5, high
```

**metrics-laptop.ini** : Laptops (fréquence réduite, économie batterie)
```ini
[System]
CPUUsage = true, 10, medium           # Moins fréquent
MemoryUsage = true, 10, medium
[Hardware]
BatteryHealth = true, 30, high        # Plus important sur laptop
BatteryStatus = true, 5, high
```

### Avantages de l'approche INI

1. **Déploiement simplifié**
   - Pousser nouvelle config via GPO
   - Pas de recompilation du code
   - Hot reload automatique

2. **Flexibilité**
   - Activer/désactiver métriques rapidement
   - Ajuster fréquences selon charge
   - Profils différents par type de machine

3. **Performance optimisée**
   - Métriques groupées par fréquence
   - Évite collectes inutiles
   - Cache des données statiques

4. **Maintenance simplifiée**
   - Commentaire = désactivation
   - Lisible par humains
   - Versionnable (Git)

5. **Debug facilité**
   - Activer temporairement verbose logging
   - Forcer collecte de métriques spécifiques
   - Ajuster timeouts sans redéployer

### Système de scheduling

Le collecteur utilise un système de scheduling intelligent :

1. **Groupement par fréquence**
   - Métriques à 5 min → Timer 1
   - Métriques à 15 min → Timer 2
   - Métriques à 60 min → Timer 3
   - Optimise le nombre de threads

2. **Event-driven pour métriques spéciales**
   - BootTime : déclenché au boot (Event Log)
   - LoginTime : déclenché au login (Event Log)
   - Fréquence = 0 dans le INI

3. **Cache pour données statiques**
   - ComputerModel, SerialNumber : collectés 1x/jour
   - Stockés en cache local
   - Réduit overhead

4. **Hot reload de configuration**
   - FileSystemWatcher sur metrics.ini
   - Recharge automatique des timers
   - Pas de redémarrage nécessaire

## Phases de développement

### Phase 1 : POC Collecteur (Focus Client) ⭐
**Objectif : Valider le concept de base avec fichier INI**

- [ ] Créer structure de base du projet client
- [ ] Implémenter ConfigParser.psm1 (lecture fichier INI)
- [ ] Créer metrics.ini avec 5 métriques basiques
  - CPUUsage (5 min)
  - MemoryUsage (5 min)
  - DiskSpace (15 min)
  - InternetConnectivity (10 min)
  - AntivirusStatus (30 min)
- [ ] Créer collecteurs basiques pour ces 5 métriques
- [ ] Implémenter système de scheduling simple
- [ ] Générer JSON valide avec timestamp
- [ ] Logger les collectes localement
- [ ] Test manuel complet

**Livrables :**
- Script PowerShell fonctionnel
- Fichier metrics.ini basique
- Logs de collecte
- JSON généré

### Phase 2 : Configuration serveur ELK (Standard)
- [ ] Setup Docker Compose pour stack ELK
- [ ] Configurer Logstash HTTP input
- [ ] Créer pipeline basique (parse JSON)
- [ ] Configurer index template Elasticsearch
- [ ] Créer dashboard Kibana simple
- [ ] Tester envoi de données du collecteur → ELK
- [ ] Valider bout-en-bout

### Phase 3 : Enrichissement collecteur
**Objectif : Ajouter toutes les métriques et fonctionnalités avancées**

#### 3.1 Métriques complètes
- [ ] Implémenter tous les collecteurs
  - SystemMetrics.psm1 complet
  - NetworkMetrics.psm1 complet
  - ApplicationMetrics.psm1 complet
  - SecurityMetrics.psm1 complet
  - UserExperienceMetrics.psm1
  - HardwareMetrics.psm1
  - EventMetrics.psm1
- [ ] Enrichir metrics.ini avec toutes les métriques
- [ ] Créer profils (server, desktop, laptop)

#### 3.2 Fonctionnalités avancées
- [ ] Implémenter DataSender.psm1 (envoi HTTP vers Logstash)
- [ ] Buffer local si Logstash indisponible
- [ ] Retry logic avec backoff exponentiel
- [ ] Hot reload de configuration (FileSystemWatcher)
- [ ] Event-driven metrics (BootTime, LoginTime)
- [ ] Cache pour données statiques
- [ ] Gestion erreurs robuste
- [ ] Logging structuré
- [ ] Performance monitoring (impact CPU/RAM)

#### 3.3 Tests
- [ ] Tests unitaires par collecteur
- [ ] Tests de performance (overhead)
- [ ] Tests de résilience (Logstash down)
- [ ] Tests de charge (1000+ endpoints simulés)

### Phase 4 : Déploiement et automation
**Objectif : Industrialiser le déploiement**

- [ ] Script d'installation automatique (Install-DEXAgent.ps1)
- [ ] Création service Windows / Tâche planifiée
- [ ] Script de désinstallation propre
- [ ] Packaging (optionnel : MSI/MSIX)
- [ ] Documentation déploiement GPO
- [ ] Script de mise à jour automatique
- [ ] Gestion des versions (versionning collecteur)
- [ ] Rollback automatique si erreur
- [ ] Tests déploiement multi-machines

### Phase 5 : Analytics et dashboards
**Objectif : Exploiter les données collectées**

- [ ] Optimiser pipeline Logstash (filtres, enrichissement)
- [ ] Index templates Elasticsearch optimisés
- [ ] Index Lifecycle Management (ILM)
- [ ] Retention policies configurables
- [ ] Dashboards Kibana avancés
  - Overview général
  - Performance système
  - Applications
  - Sécurité
  - Réseau
  - Expérience utilisateur
- [ ] Alertes Elasticsearch (Watcher ou Kibana Alerts)
- [ ] Rapports automatiques (PDF)
- [ ] Intégrations (Teams, Slack, email)

### Phase 6 : Fonctionnalités avancées (Optionnel)
**Objectif : Fonctionnalités type Nexthink avancé**

- [ ] Détection d'anomalies (Elasticsearch ML)
- [ ] Corrélation d'événements
- [ ] Remédiation automatique (scripts PowerShell déclenchés)
- [ ] API REST pour requêtes custom
- [ ] Interface web custom (React/Vue)
- [ ] Intégrations ITSM (ServiceNow, Jira)
- [ ] Threat intelligence (intégration VirusTotal API)
- [ ] Network flow analysis avancé
- [ ] User behavior analytics

### Phase 7 : Production et monitoring
**Objectif : Opérations en production**

- [ ] Monitoring de la stack ELK elle-même
- [ ] Alertes sur agents silencieux
- [ ] Dashboard santé du système de monitoring
- [ ] Documentation opérationnelle complète
- [ ] Runbooks incidents
- [ ] Plan de capacity planning
- [ ] Backup/restore Elasticsearch
- [ ] DR (Disaster Recovery) plan

## Exemple de structure JSON

```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "agent_version": "1.0.0",
  "computer": {
    "hostname": "LAPTOP-USER01",
    "domain": "CORP",
    "os": "Windows 11 Pro",
    "os_build": "22621.1234",
    "manufacturer": "Dell Inc.",
    "model": "Latitude 7420",
    "serial": "ABC123XYZ"
  },
  "user": {
    "username": "jdoe",
    "domain": "CORP",
    "sid": "S-1-5-21-..."
  },
  "metrics": {
    "system": {
      "cpu_percent": 45.2,
      "memory_percent": 62.8,
      "memory_available_mb": 6144,
      "disk_c_free_gb": 125.4,
      "uptime_hours": 72
    },
    "network": {
      "primary_adapter": "Ethernet",
      "ip_address": "192.168.1.100",
      "gateway_latency_ms": 2,
      "dns_resolution_ms": 15,
      "internet_connected": true
    },
    "applications": {
      "running_count": 24,
      "top_cpu": [
        {"name": "chrome.exe", "cpu": 12.5},
        {"name": "outlook.exe", "cpu": 8.2}
      ],
      "top_memory": [
        {"name": "chrome.exe", "memory_mb": 1024},
        {"name": "teams.exe", "memory_mb": 512}
      ]
    },
    "security": {
      "antivirus_enabled": true,
      "antivirus_updated": true,
      "firewall_enabled": true,
      "windows_updates_pending": 2,
      "last_update_date": "2026-01-10"
    },
    "experience": {
      "boot_time_seconds": 45,
      "login_time_seconds": 12,
      "app_crashes_24h": 0,
      "system_freezes_24h": 1
    }
  },
  "events": [
    {
      "type": "error",
      "source": "Application",
      "event_id": 1000,
      "message": "Application crash detected"
    }
  ]
}
```

## Considérations techniques

### Architecture du collecteur client

#### Système de scheduling
```
Orchestrateur principal (DEXCollector.ps1)
    ↓
ConfigParser → Charge metrics.ini
    ↓
MetricsScheduler → Groupe par fréquence
    ↓
┌─────────────────┬──────────────────┬──────────────────┐
│  Timer 5 min    │  Timer 15 min    │  Timer 60 min    │
│  (haute freq)   │  (moyenne freq)  │  (basse freq)    │
├─────────────────┼──────────────────┼──────────────────┤
│ CPUUsage        │ DiskSpace        │ WinUpdates       │
│ MemoryUsage     │ GatewayLatency   │ BatteryHealth    │
│ ActiveConn      │ WiFiSignal       │ HW Inventory     │
└─────────────────┴──────────────────┴──────────────────┘
    ↓                   ↓                    ↓
MetricsCollector → Invoque collecteurs spécialisés
    ↓
Génération JSON → Format standardisé
    ↓
DataSender → Envoi vers Logstash (ou buffer local)
```

#### Gestion de la configuration

**Hot reload avec FileSystemWatcher :**
```
metrics.ini modifié
    ↓
FileSystemWatcher détecte changement
    ↓
Recharge configuration
    ↓
Reconfigure timers à chaud
    ↓
Pas de redémarrage nécessaire
```

**Profils selon environnement :**
- Detection automatique du type de machine
- Chargement du profil approprié
- Fallback sur profil par défaut

#### Performance et optimisation

**Groupement intelligent :**
- Métriques collectées ensemble si même source (ex: WMI)
- Réduction du nombre d'appels système
- Cache des données statiques

**Impact ressources :**
- Target < 5% CPU pendant collecte
- Pic < 10 secondes toutes les 5 minutes
- Mémoire < 50 MB
- Réseau < 10 KB par collecte

**Parallélisation :**
```powershell
# Collecte en parallèle pour métriques indépendantes
$jobs = @()
$jobs += Start-Job { Get-SystemMetrics }
$jobs += Start-Job { Get-NetworkMetrics }
$jobs | Wait-Job | Receive-Job
```

### Sécurité
- Chiffrement HTTPS pour transport des données
- Authentification API Logstash
- Pas de données sensibles dans les métriques
- Permissions minimales pour l'agent PowerShell

### Performance
- Collecte légère (< 5% CPU)
- Fréquence configurable (ex: toutes les 5 min)
- Buffer local en cas d'indisponibilité serveur
- Compression des données JSON

### Scalabilité
- Support de milliers d'endpoints
- Sharding Elasticsearch
- Load balancing Logstash
- Archivage des données anciennes

### Monitoring
- Healthcheck de l'agent
- Monitoring de la stack ELK
- Alertes si agents silencieux

## Déploiement et gestion des configurations

### Stratégie de déploiement par GPO

**Étape 1 : Déploiement initial**
```powershell
# Via GPO - Computer Configuration - Scripts - Startup
\\domain\SYSVOL\scripts\Install-DEXAgent.ps1

# Installation sur C:\ProgramData\DEXCollector
# Création service/tâche planifiée automatique
```

**Étape 2 : Distribution configuration**
```powershell
# Via GPO - Computer Configuration - Preferences - Files
Source: \\domain\SYSVOL\DEXCollector\metrics-desktop.ini
Destination: C:\ProgramData\DEXCollector\config\metrics.ini

# Mise à jour automatique à chaque refresh GPO
```

**Étape 3 : Profils par OU**
```
Domain
├── Servers OU → metrics-server.ini
├── Desktops OU → metrics-desktop.ini
├── Laptops OU → metrics-laptop.ini
└── VDI OU → metrics-vdi.ini
```

### Gestion centralisée des configurations

**Repository central :**
```
\\domain\SYSVOL\DEXCollector\
├── collector.ini                 # Config générale
├── profiles/
│   ├── metrics-server.ini
│   ├── metrics-desktop.ini
│   ├── metrics-laptop.ini
│   └── metrics-vdi.ini
├── scripts/
│   └── Update-ConfigVersion.ps1  # Script de rollout
└── versions/
    ├── v1.0.0/
    ├── v1.1.0/
    └── current → v1.1.0 (symlink)
```

**Mise à jour configuration :**
```powershell
# Modifier metrics.ini sur le share
# Les agents rechargent automatiquement (hot reload)
# Ou forcer refresh :
Invoke-GPUpdate -Computer "DESKTOP-001" -Force
```

### Versions et rollback

**Versionning automatique :**
```ini
# metrics.ini
[Metadata]
ConfigVersion = 1.2.0
LastModified = 2026-01-15T10:30:00Z
MinCollectorVersion = 1.0.0

# Le collecteur vérifie compatibilité
```

**Rollback en cas de problème :**
```powershell
# Via script ou manuel
Copy-Item "versions\v1.0.0\metrics.ini" -Destination "current\"
# Les agents rechargent automatiquement
```

### Monitoring du déploiement

**Validation déploiement :**
- Dashboards Kibana montrent version config par machine
- Alertes si version obsolète détectée
- Rapport de conformité automatique

## Monitoring

## Technologies et dépendances

### Client
- PowerShell 5.1+ (compatible Windows 10/11)
- Modules optionnels : PSWindowsUpdate, etc.

### Serveur
- Elasticsearch 8.x
- Logstash 8.x
- Kibana 8.x
- Docker & Docker Compose (pour déploiement)

## Ressources et références

### Documentation
- [PowerShell Documentation](https://docs.microsoft.com/powershell/)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Logstash Documentation](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Kibana Guide](https://www.elastic.co/guide/en/kibana/current/index.html)

### Inspiration
- Nexthink architecture
- Windows Performance Counters
- SIEM best practices

## Décisions d'architecture importantes

### ✅ Pourquoi fichiers INI plutôt que JSON/YAML ?

**Avantages INI :**
- ✅ Format simple, lisible par tous
- ✅ Commentaires natifs (#)
- ✅ Facile à éditer manuellement
- ✅ Pas de risque d'erreur de syntaxe complexe
- ✅ PowerShell parse nativement (ou facilement)

**Comparaison :**
```ini
# INI - Simple et clair
[System]
CPUUsage = true, 5, high
# MemoryUsage = true, 5, high  ← Désactivé par commentaire
```

```json
// JSON - Plus verbeux, pas de commentaires standards
{
  "System": {
    "CPUUsage": {
      "enabled": true,
      "frequency": 5,
      "priority": "high"
    }
  }
}
```

### ✅ Pourquoi fréquences différenciées par métrique ?

**Raisons :**
1. **Performance** : Éviter overhead inutile
   - CPU/RAM : changent rapidement → 5 min
   - Model/Serial : statiques → 1x/jour
   
2. **Réseau** : Réduire trafic
   - Métriques critiques : haute fréquence
   - Inventaire : basse fréquence
   
3. **Flexibilité** : Adapter selon contexte
   - Serveurs critiques : fréquence élevée
   - Laptops : fréquence réduite (batterie)

### ✅ Pourquoi PowerShell plutôt que Python/C# ?

**Avantages PowerShell :**
- ✅ Natif Windows (pré-installé)
- ✅ Accès direct WMI/CIM
- ✅ Accès direct Event Logs
- ✅ Pas de dépendances externes
- ✅ Intégration parfaite GPO
- ✅ Signing de scripts natif
- ✅ Expertise répandue en entreprise

### ✅ Service Windows vs Tâche planifiée ?

**Recommandation : Tâche planifiée**

**Avantages :**
- ✅ Plus simple à déployer (GPO)
- ✅ Pas besoin droits admin pour modifier
- ✅ Logs intégrés Windows
- ✅ Retry automatique si échec
- ✅ Visible dans Task Scheduler

**Service Windows si :**
- Besoin de monitoring temps réel (< 1 min)
- Besoin de réactivité immédiate
- Contexte serveur critique

### ✅ Buffer local : Pourquoi et comment ?

**Pourquoi :**
- Logstash peut être indisponible (réseau, maintenance)
- Pas de perte de données
- Garantie de livraison

**Comment :**
```
C:\ProgramData\DEXCollector\buffer\
├── 2026-01-15_10-00.json  ← En attente d'envoi
├── 2026-01-15_10-05.json
└── 2026-01-15_10-10.json
```

**Mécanisme :**
1. Collecte → Génère JSON
2. Tentative envoi Logstash
3. Si échec → Sauvegarde dans buffer
4. Retry périodique (backoff exponentiel)
5. Nettoyage après envoi réussi
6. Limite taille buffer (ex: 100 MB)

## Prochaines étapes pour démarrer

### 🎯 Phase 1 : POC Collecteur client (2-3 jours)

**Jour 1 : Setup de base**
1. Créer structure projet
   ```
   client/
   ├── DEXCollector.ps1
   ├── config/
   │   └── metrics.ini
   └── modules/
       └── ConfigParser.psm1
   ```

2. Créer metrics.ini minimal (5 métriques)
   ```ini
   [System]
   CPUUsage = true, 5, high
   MemoryUsage = true, 5, high
   DiskSpace = true, 15, medium
   
   [Network]
   InternetConnectivity = true, 10, high
   
   [Security]
   AntivirusStatus = true, 30, high
   ```

3. Implémenter ConfigParser.psm1
   - Lecture et parsing du INI
   - Validation des valeurs
   - Retour d'objets PowerShell

**Jour 2 : Collecteurs et scheduling**
4. Créer collecteurs basiques
   - SystemMetrics.psm1 (CPU, RAM, Disk)
   - NetworkMetrics.psm1 (connectivité)
   - SecurityMetrics.psm1 (AV status)

5. Implémenter scheduling simple
   - Groupement par fréquence
   - Boucle principale avec tracking
   - Génération JSON avec timestamp

**Jour 3 : Tests et logging**
6. Ajouter logging local
7. Tests manuels complets
8. Validation du JSON généré
9. Documentation du POC

**Livrable Phase 1 :**
- Collecteur fonctionnel avec 5 métriques
- Configuration INI opérationnelle
- JSON valide généré
- Logs de collecte

### Phase 2 : Stack ELK (1 jour)

**Objectif : Valider bout-en-bout**

1. **Setup de l'environnement de dev**
   - Docker Compose avec stack ELK
   - Configuration Logstash HTTP input
   - Index template Elasticsearch basique

2. **Configurer pipeline Logstash**
   ```conf
   input {
     http {
       port => 5044
       codec => json
     }
   }
   
   filter {
     # Enrichissement basique
   }
   
   output {
     elasticsearch {
       hosts => ["elasticsearch:9200"]
       index => "dex-metrics-%{+YYYY.MM.dd}"
     }
   }
   ```

3. **Intégration collecteur → Logstash**
   - Ajouter DataSender.psm1
   - Envoi HTTP POST vers Logstash
   - Test bout-en-bout

4. **Créer dashboard Kibana**
   - Visualisation temps réel
   - Graphiques basiques (CPU, RAM, Disk)

**Livrable Phase 2 :**
- Stack ELK fonctionnelle (Docker)
- Données visibles dans Kibana
- Pipeline validé bout-en-bout

### Phase 3 : Extension (1-2 semaines)

**À partir du POC validé :**
- Ajouter toutes les métriques (30-40 métriques)
- Implémenter buffer local
- Hot reload de configuration
- Event-driven metrics (boot, login)
- Tests unitaires et performance
- Scripts d'installation

### Points d'attention pour démarrer

✅ **Commencer simple**
- Ne pas essayer de tout faire d'un coup
- POC avec 5 métriques suffit pour validation
- Ajouter fonctionnalités progressivement

✅ **Tests fréquents**
- Tester chaque métrique individuellement
- Valider le JSON généré
- Vérifier l'impact performance (CPU/RAM)

✅ **Documentation continue**
- Documenter les décisions
- Commenter le code
- Créer des exemples

✅ **Itération rapide**
- POC en 2-3 jours max
- Feedback rapide
- Ajustements selon résultats

## Notes
- Privilégier la simplicité au début
- Itérer rapidement sur le POC
- Documenter au fur et à mesure
- Prévoir les cas d'erreur dès le début
