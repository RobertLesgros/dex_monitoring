# Configuration DEX Collector

Ce dossier contient les fichiers de configuration du collecteur DEX.

## Fichiers de configuration

### metrics.ini

Configure les métriques à collecter et leurs fréquences.

**Format:**
```ini
[Section]
MetricName = enabled, frequency_minutes, priority
```

- `enabled`: `true` ou `false` pour activer/désactiver
- `frequency_minutes`: Intervalle de collecte en minutes (0 = event-driven)
- `priority`: `high`, `medium` ou `low`

**Exemple:**
```ini
[System]
CPUUsage = true, 5, high      # Collecte toutes les 5 minutes
MemoryUsage = true, 5, high
DiskSpace = true, 15, medium  # Collecte toutes les 15 minutes
```

### collector.ini

Configure le comportement général du collecteur.

**Sections principales:**

- `[General]`: Version, niveau de log
- `[Logstash]`: Endpoint, authentification, timeouts
- `[Buffer]`: Buffer local en cas d'indisponibilité serveur
- `[Logging]`: Configuration des logs locaux
- `[Performance]`: Limites CPU, délais de collecte

## Profils

Le dossier `profiles/` contient des configurations pré-définies:

| Profil | Description | Cas d'usage |
|--------|-------------|-------------|
| `metrics-desktop.ini` | Configuration standard | Postes de travail |
| `metrics-server.ini` | Monitoring intensif | Serveurs critiques |
| `metrics-laptop.ini` | Économie d'énergie | Laptops nomades |

### Utilisation d'un profil

Copiez le profil souhaité vers `metrics.ini`:
```powershell
Copy-Item profiles/metrics-laptop.ini -Destination metrics.ini
```

## Hot Reload

Le collecteur supporte le rechargement automatique de la configuration.
Modifiez simplement `metrics.ini` et les changements seront appliqués
sans redémarrage.

## Désactiver une métrique

Deux méthodes:
1. Mettre `enabled` à `false`: `CPUUsage = false, 5, high`
2. Commenter la ligne: `# CPUUsage = true, 5, high`

## Bonnes pratiques

1. **Fréquences**: Ajustez selon les besoins réels
   - Métriques critiques: 2-5 minutes
   - Métriques standard: 10-15 minutes
   - Données statiques: 1440 minutes (1x/jour)

2. **Impact performance**: Gardez < 5% CPU
   - Moins de métriques simultanées
   - Augmentez les délais entre collectes

3. **Buffer**: Activez pour garantir aucune perte de données

4. **Logs**: Utilisez `DEBUG` uniquement pour le dépannage
