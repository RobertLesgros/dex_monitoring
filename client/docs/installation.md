# Guide d'installation DEX Collector

## Prérequis

- Windows 10/11 ou Windows Server 2016+
- PowerShell 5.1 ou supérieur
- Droits administrateur pour l'installation
- Accès réseau vers le serveur Logstash

## Installation manuelle

### 1. Copier les fichiers

```powershell
# Créer le répertoire d'installation
$installPath = "C:\ProgramData\DEXCollector"
New-Item -Path $installPath -ItemType Directory -Force

# Copier les fichiers du client
Copy-Item -Path ".\client\*" -Destination $installPath -Recurse
```

### 2. Configurer le collecteur

Éditez `C:\ProgramData\DEXCollector\config\collector.ini`:

```ini
[Logstash]
Endpoint = https://votre-serveur-logstash:5044
UseAuthentication = false

[Logging]
LogPath = C:\ProgramData\DEXCollector\logs
LogLevel = INFO
```

### 3. Configurer les métriques

Éditez `C:\ProgramData\DEXCollector\config\metrics.ini` ou utilisez un profil:

```powershell
# Utiliser le profil laptop
Copy-Item "config\profiles\metrics-laptop.ini" -Destination "config\metrics.ini"
```

### 4. Tester l'installation

```powershell
cd C:\ProgramData\DEXCollector
.\DEXCollector.ps1 -RunOnce -TestMode

# Vérifier le fichier JSON généré
Get-ChildItem export\*.json | Select-Object -First 1 | Get-Content
```

## Déploiement par GPO

### 1. Préparer le partage réseau

```
\\domain\SYSVOL\DEXCollector\
├── Install-DEXAgent.ps1
├── collector.ini
└── profiles\
    ├── metrics-desktop.ini
    ├── metrics-laptop.ini
    └── metrics-server.ini
```

### 2. Script d'installation GPO

```powershell
# Install-DEXAgent.ps1
$installPath = "C:\ProgramData\DEXCollector"
$sourcePath = "\\domain\SYSVOL\DEXCollector"

# Copier les fichiers
robocopy "$sourcePath\client" $installPath /MIR /R:3 /W:5

# Appliquer le profil selon le type de machine
$isLaptop = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes -in @(9, 10, 14)
$profile = if ($isLaptop) { "laptop" } else { "desktop" }
Copy-Item "$sourcePath\profiles\metrics-$profile.ini" -Destination "$installPath\config\metrics.ini" -Force
```

### 3. Configurer la GPO

1. Ouvrir Group Policy Management
2. Créer une nouvelle GPO
3. Computer Configuration → Preferences → Scheduled Tasks
4. Ajouter une tâche planifiée:
   - Action: Start a program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "C:\ProgramData\DEXCollector\DEXCollector.ps1"`
   - Trigger: At startup, puis répéter toutes les 5 minutes

## Exécution comme service

Pour une exécution continue, créez un service Windows avec NSSM:

```powershell
# Télécharger NSSM: https://nssm.cc/
nssm install DEXCollector "powershell.exe" "-ExecutionPolicy Bypass -File C:\ProgramData\DEXCollector\DEXCollector.ps1"
nssm set DEXCollector DisplayName "DEX Collector Service"
nssm set DEXCollector Description "Digital Experience Monitoring Agent"
nssm start DEXCollector
```

## Vérification

### Vérifier les logs

```powershell
Get-Content "C:\ProgramData\DEXCollector\logs\dexcollector.log" -Tail 50
```

### Vérifier les exports JSON

```powershell
Get-ChildItem "C:\ProgramData\DEXCollector\export\*.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 5
```

### Tester la connectivité Logstash

```powershell
Test-NetConnection -ComputerName "logstash.example.com" -Port 5044
```

## Désinstallation

```powershell
# Arrêter le service si existe
Stop-Service DEXCollector -ErrorAction SilentlyContinue
nssm remove DEXCollector confirm

# Supprimer les fichiers
Remove-Item -Path "C:\ProgramData\DEXCollector" -Recurse -Force
```

## Dépannage

### Le collecteur ne démarre pas

1. Vérifier la version PowerShell: `$PSVersionTable.PSVersion`
2. Vérifier les droits d'exécution: `Get-ExecutionPolicy`
3. Exécuter en mode debug: `.\DEXCollector.ps1 -TestMode -Verbose`

### Pas de données dans Kibana

1. Vérifier les logs locaux
2. Vérifier le buffer: `Get-ChildItem C:\ProgramData\DEXCollector\buffer`
3. Tester la connectivité vers Logstash

### Impact CPU élevé

1. Réduire les fréquences dans `metrics.ini`
2. Désactiver les métriques non essentielles
3. Utiliser le profil laptop pour économiser les ressources
