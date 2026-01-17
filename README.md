# XMRig Dashboard

Dashboard Flask pour superviser des miners XMRig (stats live, historique, gestion des miners).

## Prerequis

- Windows + PowerShell
- Python 3.10+ recommande

## Installation rapide

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Lancer l'application

```powershell
.\.venv\Scripts\python.exe app.py
```

Ouvrir ensuite http://127.0.0.1:5000

## Premiere ouverture (setup admin)

Si aucun utilisateur n'existe, l'app redirige vers `/setup` pour creer le compte admin.

Champs requis:
- Nom d'utilisateur
- Mot de passe (8 caracteres minimum)

## Scripts utiles

- Creer les tables:
  ```powershell
  .\.venv\Scripts\python.exe init_db.py
  ```
- Creer un admin (cree aussi les tables si besoin):
  ```powershell
  .\.venv\Scripts\python.exe create_admin.py
  ```
- Forcer un admin avec variables d'environnement:
  ```powershell
  $env:ADMIN_USERNAME="admin"
  $env:ADMIN_PASSWORD="mon-mdp-solide"
  .\.venv\Scripts\python.exe create_admin.py
  ```

## Configuration

Le fichier `config.py` lit:

- `SECRET_KEY`
- `DATABASE_URL`

Par defaut, la base SQLite est dans `instance/xmrig_dashboard.db`.

## Configurer une instance XMRig

Le dashboard lit l'API HTTP de XMRig (`/2/summary`).

1) Ouvrir le fichier `config.json` de XMRig
2) Activer l'API HTTP et definir un token

Exemple:

```json
{
  "http": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 18080,
    "access-token": "mon-token"
  }
}
```

Notes:
- Utiliser l'IP du miner et le port `http.port` dans le dashboard.
- Copier la valeur de `access-token` dans le champ "Access token" du miner.
- Ouvrir le port dans le firewall si besoin (ex: 18080).

## Depannage

- Erreur `no such table: users`:
  - La base a ete supprimee. Relancer `create_admin.py` ou `init_db.py`, puis redemarrer l'app.
