import os

import bcrypt

from app import create_app
from models.models import db, User

app = create_app()

username = os.environ.get("ADMIN_USERNAME", "admin")
password = os.environ.get("ADMIN_PASSWORD", "admin")

with app.app_context():
    db.create_all()

    if User.query.filter_by(username=username).first():
        print(f"Admin user already exists: {username}")
    else:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        user = User(username=username, password_hash=hashed.decode("utf-8"))
        db.session.add(user)
        db.session.commit()
        print("Admin user created:")
        print(f"  username = {username}")
        print(f"  password = {password}")
