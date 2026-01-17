from flask import Flask, render_template, redirect, url_for, request, flash
from config import Config
from models.models import db, User
from pathlib import Path
import requests
from requests.exceptions import RequestException, Timeout
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import bcrypt
import threading
import time

# --------------------------------------------------------------------
#   Fonction utilitaire : tester l’API XMRig d’un miner
# --------------------------------------------------------------------
def ping_miner_api(miner):
    """
    Interroge l'API HTTP de XMRig.
    Retourne (ok: bool, message: str)
    """
    url = f"http://{miner.host}:{miner.port}/2/summary"
    headers = {"Authorization": f"Bearer {miner.access_token}"}

    try:
        resp = requests.get(url, headers=headers, timeout=3)
        resp.raise_for_status()

        data = resp.json()
        hashrate_list = data.get("hashrate", {}).get("total", [])

        hash_10s = hashrate_list[0] if len(hashrate_list) > 0 else None

        if hash_10s is not None:
            return True, f"OK - {hash_10s} H/s (10s)"
        else:
            return True, "OK - hashrate non disponible"

    except Exception as e:
        return False, f"Erreur: {e}"


# Login manager global
login_manager = LoginManager()

def get_miner_stats(miner):
    """
    Interroge un miner XMRig et renvoie un dict :
    {
        "status": "online/offline",
        "hash_10s": float | None,
        "hash_60s": float | None,
        "hash_15m": float | None,
        "algo": str | None,
        "pool": str | None,
        "raw": {} (optionnel)
    }
    """

    url = f"http://{miner.host}:{miner.port}/2/summary"
    headers = {
        "Authorization": f"Bearer {miner.access_token}"
    }

    try:
        r = requests.get(url, headers=headers, timeout=2)
        if r.status_code != 200:
            return {"status": "offline"}

        data = r.json()
        total = data.get("hashrate", {}).get("total", [])

        return {
            "status": "online",
            "hash_10s": total[0] if len(total) > 0 else None,
            "hash_60s": total[1] if len(total) > 1 else None,
            "hash_15m": total[2] if len(total) > 2 else None,
            "algo": data.get("algo"),
            "pool": data.get("connection", {}).get("pool"),
            "raw": data
        }

    except (RequestException, Timeout, ValueError):
        return {"status": "offline"}

def start_collector_background(app):
    """
    Lance un thread qui collecte automatiquement les stats.
    Le comportement (enabled + intervalle) est lu dans la table 'settings'.
    """

    def collector_loop():
        from models.models import Miner, MinerStat, Setting, db
        from sqlalchemy.exc import OperationalError

        print("[collector] Thread de collecte démarré.")
        while True:
            # Valeurs par défaut en cas de souci
            interval = app.config.get("COLLECTOR_DEFAULT_INTERVAL_SECONDS", 900)

            try:
                with app.app_context():
                    default_enabled = app.config.get("COLLECTOR_DEFAULT_ENABLED", False)
                    default_interval = app.config.get("COLLECTOR_DEFAULT_INTERVAL_SECONDS", 900)

                    try:
                        s_enabled = Setting.query.filter_by(key="collector_enabled").first()
                        s_interval = Setting.query.filter_by(key="collector_interval").first()
                    except OperationalError as e:
                        # Table settings pas encore créée
                        print("[collector] Table 'settings' manquante. Lance 'python init_db.py' puis redémarre l'app.")
                        print(f"[collector] Détail : {e}")
                        time.sleep(60)
                        continue

                    enabled = default_enabled
                    if s_enabled:
                        enabled = (s_enabled.value == "1")

                    interval = default_interval
                    if s_interval and s_interval.value and s_interval.value.isdigit():
                        interval = int(s_interval.value)

                    if not enabled:
                        print("[collector] Désactivé via l'interface (collector_enabled = 0).")
                        time.sleep(60)
                        continue

                    miners = Miner.query.filter_by(enabled=True).all()
                    if not miners:
                        print("[collector] Aucun miner enabled.")
                    else:
                        print(f"[collector] Collecte sur {len(miners)} miner(s)...")

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
                        print("[collector] Collecte enregistrée.")

            except Exception as e:
                print(f"[collector] Erreur inattendue: {e}")
                # on laisse dormir un peu avant de retenter
                time.sleep(60)
                continue

            # si tout s'est bien passé, on dort le délai normal
            time.sleep(interval)

    t = threading.Thread(target=collector_loop, daemon=True)
    t.start()


# --------------------------------------------------------------------
#   Fonction de création de l’app Flask
# --------------------------------------------------------------------
def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    # Création du dossier instance/
    instance_path = Path(app.instance_path)
    instance_path.mkdir(parents=True, exist_ok=True)

    # Initialisation des extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    with app.app_context():
        db.create_all()

    # Chargement de l'utilisateur pour Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

    def has_users():
        try:
            return db.session.query(User.id).first() is not None
        except Exception:
            return False

    @app.before_request
    def ensure_first_run():
        if request.endpoint in ("setup", "static"):
            return None
        if request.endpoint is None:
            return None
        if not has_users():
            return redirect(url_for("setup"))

    # ----------------------------------------------------------------
    #   ROUTES
    # ----------------------------------------------------------------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if has_users():
            return redirect(url_for("login"))

        error = None

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not username or not password or not confirm:
                error = "All fields are required."
            elif password != confirm:
                error = "Password confirmation does not match."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            else:
                if User.query.filter_by(username=username).first():
                    error = "User already exists."
                else:
                    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                    user = User(username=username, password_hash=hashed)
                    db.session.add(user)
                    db.session.commit()
                    flash("Admin account created. Please log in.", "success")
                    return redirect(url_for("login"))

        return render_template("setup.html", error=error)

    # ------------------ LOGIN ------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        error = None

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            user = User.query.filter_by(username=username).first()

            if not user:
                error = "Utilisateur ou mot de passe invalide."
            else:
                if bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
                    login_user(user)
                    return redirect(url_for("dashboard"))
                else:
                    error = "Utilisateur ou mot de passe invalide."

        return render_template("login.html", error=error)

    # ------------------ LOGOUT ------------------

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # ------------------ DASHBOARD ------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        from models.models import Miner

        miners = Miner.query.order_by(Miner.name).all()

        miners_stats = []
        total_hash_10s = 0.0
        online_count = 0
        offline_count = 0

        for m in miners:
            # Miner désactivé
            if not m.enabled:
                stats = {"status": "disabled"}
                miners_stats.append({
                    "miner": m,
                    "stats": stats
                })
                continue

            # Miner activé -> on interroge XMRig
            stats = get_miner_stats(m)

            if stats.get("status") == "online":
                online_count += 1
                h10 = stats.get("hash_10s")
                if isinstance(h10, (int, float)):
                    total_hash_10s += h10
            else:
                offline_count += 1

            miners_stats.append({
                "miner": m,
                "stats": stats
            })

        return render_template(
            "dashboard.html",
            miners_stats=miners_stats,
            total_hash_10s=total_hash_10s,
            online_count=online_count,
            offline_count=offline_count
        )


    # ------------------ MINERS LIST ------------------

    @app.route("/miners")
    @login_required
    def miners_list():
        from models.models import Miner
        miners = Miner.query.order_by(Miner.name).all()
        return render_template("miners_list.html", miners=miners)

    # ------------------ MINERS NEW ------------------

    @app.route("/miners/new", methods=["GET", "POST"])
    @login_required
    def miner_new():
        from models.models import Miner

        if request.method == "POST":
            name = request.form["name"]
            host = request.form["host"]
            port = int(request.form["port"])
            token = request.form["access_token"]
            miner_type = request.form["miner_type"]
            group = request.form["group"]
            notes = request.form["notes"]

            miner = Miner(
                name=name,
                host=host,
                port=port,
                access_token=token,
                miner_type=miner_type,
                group=group,
                notes=notes,
                enabled=True,
            )
            db.session.add(miner)
            db.session.commit()

            return redirect(url_for("miners_list"))

        return render_template("miner_form.html", miner=None)

    # ------------------ MINERS EDIT ------------------

    @app.route("/miners/<int:miner_id>/edit", methods=["GET", "POST"])
    @login_required
    def miner_edit(miner_id):
        from models.models import Miner

        miner = Miner.query.get_or_404(miner_id)

        if request.method == "POST":
            miner.name = request.form["name"]
            miner.host = request.form["host"]
            miner.port = int(request.form["port"])
            miner.access_token = request.form["access_token"]
            miner.miner_type = request.form["miner_type"]
            miner.group = request.form["group"]
            miner.notes = request.form["notes"]
            miner.enabled = ("enabled" in request.form)

            db.session.commit()
            return redirect(url_for("miners_list"))

        return render_template("miner_form.html", miner=miner)

    # ------------------ MINERS DELETE ------------------

    @app.route("/miners/<int:miner_id>/delete", methods=["POST"])
    @login_required
    def miner_delete(miner_id):
        from models.models import Miner

        miner = Miner.query.get_or_404(miner_id)
        db.session.delete(miner)
        db.session.commit()

        return redirect(url_for("miners_list"))
    
    # ------------------------------------
    #  MINERS - DÉTAIL
    # ------------------------------------
    @app.route("/miners/<int:miner_id>")
    @login_required
    def miner_detail(miner_id):
        from models.models import Miner

        miner = Miner.query.get_or_404(miner_id)

        # Stats LIVE
        if miner.enabled:
            stats = get_miner_stats(miner)
        else:
            stats = {"status": "disabled"}

        return render_template(
            "miner_detail.html",
            miner=miner,
            stats=stats
        )



    # ------------------ MINERS TEST (nouveau) ------------------

    @app.route("/miners/<int:miner_id>/test", methods=["POST"])
    @login_required
    def miner_test(miner_id):
        from models.models import Miner

        miner = Miner.query.get_or_404(miner_id)
        ok, message = ping_miner_api(miner)

        flash(f"Test {miner.name}: {message}", "success" if ok else "error")
        return redirect(url_for("miners_list"))

    # ------------------------------------
    #  MINERS - HISTORIQUE (GRAPH SVG)
    # ------------------------------------
    @app.route("/miners/<int:miner_id>/history")
    @login_required
    def miner_history(miner_id):
        from models.models import Miner, MinerStat

        miner = Miner.query.get_or_404(miner_id)

        stats = (
            MinerStat.query
            .filter_by(miner_id=miner.id)
            .order_by(MinerStat.timestamp.asc())
            .limit(200)
            .all()
        )

        # On utilise maintenant hash_15m
        points = [(s.timestamp, s.hash_15m) for s in stats if s.hash_15m is not None]


        svg_path = None
        max_hash = None
        start_ts = stats[0].timestamp if stats else None
        end_ts = stats[-1].timestamp if stats else None

        if points:
            # Construire un path SVG simple

            width = 800
            height = 200
            pad_x = 30
            pad_y = 20

            n = len(points)
            max_hash = max(v for (_, v) in points) or 1.0

            # Pour éviter division par zéro si un seul point
            step_x = (width - 2 * pad_x) / (n - 1) if n > 1 else 0

            def scale(i, value):
                x = pad_x + i * step_x
                # y inversé (0 en haut dans SVG)
                ratio = value / max_hash if max_hash > 0 else 0
                y = height - pad_y - ratio * (height - 2 * pad_y)
                return x, y

            path_cmds = []
            for i, (_, val) in enumerate(points):
                x, y = scale(i, val)
                if i == 0:
                    path_cmds.append(f"M {x:.2f} {y:.2f}")
                else:
                    path_cmds.append(f"L {x:.2f} {y:.2f}")

            svg_path = " ".join(path_cmds)

        return render_template(
            "miner_history.html",
            miner=miner,
            stats_count=len(stats),
            max_hash=max_hash,
            start_ts=start_ts,
            end_ts=end_ts,
            svg_path=svg_path,
        )
    
    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        from models.models import Setting, db, User
        from flask import current_app

        default_enabled = current_app.config.get("COLLECTOR_DEFAULT_ENABLED", True)
        default_interval = current_app.config.get("COLLECTOR_DEFAULT_INTERVAL_SECONDS", 900)

        if request.method == "POST":
            form_name = request.form.get("form_name")

            # --------------------------
            #  FORMULAIRE COLLECTEUR
            # --------------------------
            if form_name == "collector":
                enabled = "collector_enabled" in request.form
                minutes_str = request.form.get("collector_interval_minutes", "15")

                try:
                    minutes = int(minutes_str)
                    if minutes < 1:
                        minutes = 1
                    if minutes > 1440:
                        minutes = 1440
                except ValueError:
                    minutes = 15

                interval_seconds = minutes * 60

                def set_setting(key, value):
                    s = Setting.query.filter_by(key=key).first()
                    if not s:
                        s = Setting(key=key, value=value)
                        db.session.add(s)
                    else:
                        s.value = value

                set_setting("collector_enabled", "1" if enabled else "0")
                set_setting("collector_interval", str(interval_seconds))

                db.session.commit()
                flash("Paramètres de collecte mis à jour.", "success")
                return redirect(url_for("settings"))

            # --------------------------
            #  FORMULAIRE MOT DE PASSE
            # --------------------------
            elif form_name == "password":
                current_pwd = request.form.get("current_password", "")
                new_pwd = request.form.get("new_password", "")
                confirm_pwd = request.form.get("confirm_password", "")

                # Validation basique
                if not current_pwd or not new_pwd or not confirm_pwd:
                    flash("Tous les champs de mot de passe sont requis.", "error")
                    return redirect(url_for("settings"))

                if new_pwd != confirm_pwd:
                    flash("La confirmation du mot de passe ne correspond pas.", "error")
                    return redirect(url_for("settings"))

                if len(new_pwd) < 8:
                    flash("Le nouveau mot de passe doit contenir au moins 8 caractères.", "error")
                    return redirect(url_for("settings"))

                # Récupérer l'utilisateur courant
                user = User.query.get(current_user.id)
                if not user:
                    flash("Utilisateur introuvable.", "error")
                    return redirect(url_for("settings"))

                # Vérifier l'ancien mot de passe
                if not bcrypt.checkpw(current_pwd.encode("utf-8"), user.password_hash.encode("utf-8")):
                    flash("Mot de passe actuel incorrect.", "error")
                    return redirect(url_for("settings"))

                # Générer le nouveau hash
                new_hash = bcrypt.hashpw(new_pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                user.password_hash = new_hash
                db.session.commit()

                flash("Mot de passe mis à jour avec succès.", "success")
                return redirect(url_for("settings"))

        # --------------------------
        #  GET : afficher les valeurs actuelles
        # --------------------------
        s_enabled = Setting.query.filter_by(key="collector_enabled").first()
        s_interval = Setting.query.filter_by(key="collector_interval").first()

        if s_enabled:
            collector_enabled = (s_enabled.value == "1")
        else:
            collector_enabled = default_enabled

        if s_interval and s_interval.value and s_interval.value.isdigit():
            interval_seconds = int(s_interval.value)
        else:
            interval_seconds = default_interval

        collector_interval_minutes = interval_seconds // 60

        return render_template(
            "settings.html",
            collector_enabled=collector_enabled,
            collector_interval_minutes=collector_interval_minutes,
        )


    @app.route("/history/combo")
    @login_required
    def history_combo():
        from models.models import Miner, MinerStat
        from collections import defaultdict

        # Lire les miners
        miners = Miner.query.order_by(Miner.id.asc()).all()

        # Charger les 500 derniers stat
        stats = (
            MinerStat.query
            .order_by(MinerStat.timestamp.asc())
            .limit(500)
            .all()
        )

        # Si aucun stat → page vide
        if not stats:
            return render_template(
                "history_combo.html",
                miners=miners,
                svg_paths={},
                svg_global=None,
                colors=[],
                start_ts=None,
                end_ts=None,
            )

        # Regroupement par minute et par miner
        # buckets[(timestamp, miner_id)] = somme hash_15m
        buckets = defaultdict(lambda: defaultdict(float))

        for s in stats:
            if s.hash_15m is None:
                continue
            ts = s.timestamp.replace(second=0, microsecond=0)
            buckets[ts][s.miner_id] += s.hash_15m

        # Tri par timestamp
        timestamps = sorted(buckets.keys())
        start_ts = timestamps[0]
        end_ts = timestamps[-1]

        # Calcul global + individuels
        global_vals = []
        miner_vals = {m.id: [] for m in miners}

        for ts in timestamps:
            per_miner = buckets[ts]
            total = sum(per_miner.values())
            global_vals.append(total)

            for m in miners:
                miner_vals[m.id].append(per_miner.get(m.id, 0))

        # Echelle du graph
        max_hash = max(global_vals) if global_vals else 1
        if max_hash <= 0:
            max_hash = 1

        # Construction des paths SVG
        def make_svg_path(values, width=800, height=200, pad_x=30, pad_y=20):
            if not values:
                return None
            n = len(values)
            if n == 1:
                return None

            step_x = (width - 2 * pad_x) / (n - 1)

            def scale(i, val):
                x = pad_x + i * step_x
                ratio = val / max_hash
                y = height - pad_y - ratio * (height - 2 * pad_y)
                return x, y

            cmds = []
            for i, v in enumerate(values):
                x, y = scale(i, v)
                if i == 0:
                    cmds.append(f"M {x:.2f} {y:.2f}")
                else:
                    cmds.append(f"L {x:.2f} {y:.2f}")
            return " ".join(cmds)

        svg_global = make_svg_path(global_vals)

        svg_paths = {}
        for m in miners:
            svg_paths[m.id] = make_svg_path(miner_vals[m.id])

        # Couleurs pour chaque miner
        palette = [
            "#ff5555", "#50fa7b", "#8be9fd", "#bd93f9", "#f1fa8c",
            "#ff79c6", "#ffb86c", "#69ff94", "#9aedfe"
        ]
        colors = {m.id: palette[(m.id - 1) % len(palette)] for m in miners}

        return render_template(
            "history_combo.html",
            miners=miners,
            svg_paths=svg_paths,
            svg_global=svg_global,
            colors=colors,
            start_ts=start_ts,
            end_ts=end_ts,
        )

    return app


# --------------------------------------------------------------------
#   MAIN
# --------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    start_collector_background(app)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

