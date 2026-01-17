import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    # Clé secrète pour les sessions Flask (change-la plus tard)
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

    # Base de données SQLite dans le dossier instance/
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL")
        or f"sqlite:///{BASE_DIR / 'instance' / 'xmrig_dashboard.db'}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    COLLECTOR_DEFAULT_ENABLED = True
    COLLECTOR_DEFAULT_INTERVAL_SECONDS = 900  # 15 minutes
