import time
from datetime import datetime

from app import create_app, get_miner_stats
from models.models import db, Miner, MinerStat

# Intervalle entre 2 samples (en secondes)
INTERVAL_SECONDS = 900  # 1 minute, tu pourras ajuster

app = create_app()

def collect_once():
    """Collecte 1 sample pour tous les miners enabled."""
    with app.app_context():
        miners = Miner.query.filter_by(enabled=True).all()
        if not miners:
            print(f"[{datetime.now()}] Aucun miner enabled.")
            return

        print(f"[{datetime.now()}] Collecte sur {len(miners)} miner(s)...")

        for m in miners:
            stats = get_miner_stats(m)

            status = stats.get("status", "offline")
            h10 = stats.get("hash_10s")
            h60 = stats.get("hash_60s")
            h15 = stats.get("hash_15m")
            algo = stats.get("algo")
            pool = stats.get("pool")

            stat = MinerStat(
                miner_id=m.id,
                status=status,
                hash_10s=h10,
                hash_60s=h60,
                hash_15m=h15,
                algo=algo,
                pool=pool,
            )
            db.session.add(stat)

        db.session.commit()
        print(f"[{datetime.now()}] Collecte terminée et enregistrée.")

def main_loop():
    """Boucle infinie de collecte."""
    while True:
        collect_once()
        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    main_loop()
