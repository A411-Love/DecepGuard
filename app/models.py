from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="viewer"
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class Honeypot(db.Model):

    __tablename__ = "honeypots"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        nullable=False
    )

    honeypot_type = db.Column(
        db.String(50),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    port = db.Column(
        db.Integer,
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="inactive"
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    def __repr__(self):
        return f"<Honeypot {self.name}>"
class AttackEvent(db.Model):
    __tablename__ = "attack_events"

    id = db.Column(db.Integer, primary_key=True)

    honeypot_id = db.Column(
        db.Integer,
        db.ForeignKey("honeypots.id"),
        nullable=False
    )

    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=False)

    protocol = db.Column(db.String(20), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)

    description = db.Column(db.Text, nullable=True)

    event_source = db.Column(
        db.String(20),
        nullable=False,
        default="simulated"
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    def __repr__(self):
        return f"<AttackEvent {self.attack_type} from {self.source_ip}>"