
import os
from flask import Flask, render_template
from sqlalchemy import URL
from dotenv import load_dotenv
from flask_login import login_required
from app.extensions import db, login_manager, csrf


def create_app():
    load_dotenv()

    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

    app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
        drivername="mysql+pymysql",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        database=os.getenv("DB_NAME", "decepguard_db"),
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from app.auth import auth
    app.register_blueprint(auth, url_prefix="/auth")

    from app.honeypots import honeypots
    app.register_blueprint(honeypots, url_prefix="/honeypots")

    # Register Attack Events blueprint
    from app.events import events
    app.register_blueprint(events, url_prefix="/events")

    from app.alerts import alerts
    app.register_blueprint(alerts, url_prefix="/alerts")

    from app.incidents import incidents
    app.register_blueprint(incidents, url_prefix="/incidents")

    from app.api import api
    app.register_blueprint(api, url_prefix="/api")

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return db.session.get(User, int(user_id))

    @app.route("/")
    def home():
        return render_template("index.html")
    
    @app.route("/dashboard")
    @login_required
    def dashboard():
        from app.models import Honeypot, AttackEvent, Alert, Incident

        # Dashboard statistics
        total_honeypots = Honeypot.query.count()
        active_honeypots = Honeypot.query.filter_by(status="active").count()

        total_events = AttackEvent.query.count()
        total_alerts = Alert.query.count()

        open_incidents = Incident.query.filter(
            Incident.status.notin_(["Resolved", "Closed"])
        ).count()

        # Recent attack events
        recent_events = AttackEvent.query.order_by(
            AttackEvent.timestamp.desc()
        ).limit(5).all()

        # Attack severity statistics
        severity_counts = {
            "Low": AttackEvent.query.filter_by(severity="Low").count(),
            "Medium": AttackEvent.query.filter_by(severity="Medium").count(),
            "High": AttackEvent.query.filter_by(severity="High").count(),
            "Critical": AttackEvent.query.filter_by(severity="Critical").count()
        }

        return render_template(
            "dashboard.html",
            total_honeypots=total_honeypots,
            active_honeypots=active_honeypots,
            total_events=total_events,
            total_alerts=total_alerts,
            open_incidents=open_incidents,
            recent_events=recent_events,
            severity_counts=severity_counts
        )


    

    return app
