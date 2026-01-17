from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# ------------------------
#  USER MODEL
# ------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------
#  MINER MODEL
# ------------------------
class Miner(db.Model):
    __tablename__ = "miners"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    enabled = db.Column(db.Boolean, default=True)

    host = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    access_token = db.Column(db.String(255), nullable=False)

    miner_type = db.Column(db.String(50), default="unknown")
    group = db.Column(db.String(50), nullable=True)

    notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )
    stats = db.relationship("MinerStat", backref="miner", lazy=True)

class MinerStat(db.Model):
    __tablename__ = "miner_stats"

    id = db.Column(db.Integer, primary_key=True)
    miner_id = db.Column(db.Integer, db.ForeignKey("miners.id"), nullable=False)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    status = db.Column(db.String(16), nullable=False)  # "online", "offline"
    hash_10s = db.Column(db.Float, nullable=True)
    hash_60s = db.Column(db.Float, nullable=True)
    hash_15m = db.Column(db.Float, nullable=True)

    algo = db.Column(db.String(64), nullable=True)
    pool = db.Column(db.String(255), nullable=True)

class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=True)

