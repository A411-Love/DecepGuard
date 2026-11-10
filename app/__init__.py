import os
from flask import Flask, app, render_template
from sqlalchemy import URL
from dotenv import load_dotenv

from app import honeypots
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

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return db.session.get(User, int(user_id))

    @app.route("/")
    def home():
        return render_template("index.html")

    return app