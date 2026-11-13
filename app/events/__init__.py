from flask import (
    Blueprint, render_template, redirect,
    url_for, flash, request
)

from flask_login import login_required

from app.extensions import db
import random

from app.models import AttackEvent, Alert, Honeypot
from app.auth.permissions import role_required
from app.events.forms import AttackEventForm
from app.cowrie.importer import import_cowrie_events


events = Blueprint("events", __name__)


def prepare_form(form):
    """Load existing honeypots into the selection field."""
    honeypots = Honeypot.query.order_by(Honeypot.name).all()
    form.honeypot_id.choices = [
        (honeypot.id, honeypot.name)
        for honeypot in honeypots
    ]
    return honeypots


@events.route("/")
@login_required
def list_events():
    query = AttackEvent.query

    severity = request.args.get("severity", "")
    protocol = request.args.get("protocol", "")
    attack_type = request.args.get("attack_type", "")

    if severity:
        query = query.filter_by(severity=severity)

    if protocol:
        query = query.filter_by(protocol=protocol)

    if attack_type:
        query = query.filter(
            AttackEvent.attack_type.ilike(f"%{attack_type}%")
        )

    all_events = query.order_by(
        AttackEvent.timestamp.desc()
    ).all()

    return render_template(
        "events/list.html",
        events=all_events,
        severity=severity,
        protocol=protocol,
        attack_type=attack_type
    )


@events.route("/import-cowrie", methods=["POST"])
@role_required("admin", "analyst")
def import_cowrie():
    try:
        imported = import_cowrie_events()

        if imported:
            flash(
                f"Successfully imported {imported} Cowrie events and created alerts!",
                "success"
            )
        else:
            flash("No new Cowrie events to import.", "info")

    except FileNotFoundError:
        flash("Cowrie log file not found. Refresh the Cowrie log first.", "warning")

    except Exception as error:
        db.session.rollback()
        flash(f"Cowrie import failed: {error}", "danger")

    return redirect(url_for("events.list_events"))


@events.route("/simulate", methods=["POST"])
@role_required("admin", "analyst")
def simulate_attack():

    # Find active honeypots
    honeypots = Honeypot.query.filter_by(status="active").all()

    if not honeypots:
        flash("No active honeypots found. Activate a honeypot first.", "warning")
        return redirect(url_for("events.list_events"))

    # Select a random active honeypot
    honeypot = random.choice(honeypots)

    # Sample attack scenarios
    scenarios = [
        {
            "attack_type": "SSH Login Attempt",
            "protocol": "SSH",
            "port": 22,
            "severity": "High",
            "description": "Multiple suspicious SSH login attempts detected."
        },
        {
            "attack_type": "Port Scanning",
            "protocol": "TCP",
            "port": 80,
            "severity": "Medium",
            "description": "A simulated source scanned the honeypot service."
        },
        {
            "attack_type": "Brute Force Attempt",
            "protocol": "SSH",
            "port": 22,
            "severity": "Critical",
            "description": "Repeated password guessing activity detected."
        },
        {
            "attack_type": "Suspicious HTTP Request",
            "protocol": "HTTP",
            "port": 80,
            "severity": "Medium",
            "description": "A suspicious HTTP request was sent to the honeypot."
        }
    ]

    scenario = random.choice(scenarios)

    # Generate a simulated attack event
    event = AttackEvent(
        honeypot_id=honeypot.id,
        source_ip=f"192.0.2.{random.randint(1, 254)}",
        source_port=random.randint(1024, 65535),
        destination_port=scenario["port"],
        protocol=scenario["protocol"],
        attack_type=scenario["attack_type"],
        severity=scenario["severity"],
        description=scenario["description"],
        event_source="simulated"
    )

    db.session.add(event)
    db.session.flush()

    # Automatically create an alert
    alert = Alert(
        attack_event_id=event.id,
        title=f"{scenario['attack_type']} detected",
        description=scenario["description"],
        severity=scenario["severity"],
        status="New"
    )

    db.session.add(alert)
    db.session.commit()

    flash("Simulated attack event and alert generated successfully!", "success")
    return redirect(url_for("events.list_events"))


@events.route("/add", methods=["GET", "POST"])
@role_required("admin", "analyst")
def add_event():
    form = AttackEventForm()
    honeypots = prepare_form(form)

    if not honeypots:
        flash("Create a honeypot before adding attack events.", "warning")
        return redirect(url_for("honeypots.list_honeypots"))

    if form.validate_on_submit():
        event = AttackEvent(
            honeypot_id=form.honeypot_id.data,
            source_ip=form.source_ip.data.strip(),
            source_port=form.source_port.data,
            destination_port=form.destination_port.data,
            protocol=form.protocol.data,
            attack_type=form.attack_type.data,
            severity=form.severity.data,
            description=(form.description.data or "").strip(),
            event_source="simulated"
        )

        db.session.add(event)
        db.session.commit()

        flash("Simulated attack event created successfully!", "success")
        return redirect(url_for("events.list_events"))

    return render_template("events/form.html", form=form, title="Add Attack Event")


@events.route("/edit/<int:event_id>", methods=["GET", "POST"])
@role_required("admin", "analyst")
def edit_event(event_id):
    event = db.get_or_404(AttackEvent, event_id)
    form = AttackEventForm(obj=event)
    prepare_form(form)

    if form.validate_on_submit():
        event.honeypot_id = form.honeypot_id.data
        event.source_ip = form.source_ip.data.strip()
        event.source_port = form.source_port.data
        event.destination_port = form.destination_port.data
        event.protocol = form.protocol.data
        event.attack_type = form.attack_type.data
        event.severity = form.severity.data
        event.description = (form.description.data or "").strip()

        db.session.commit()

        flash("Attack event updated successfully!", "success")
        return redirect(url_for("events.list_events"))

    return render_template(
        "events/form.html",
        form=form,
        title="Edit Attack Event"
    )


@events.route("/delete/<int:event_id>", methods=["POST"])
@role_required("admin", "analyst")
def delete_event(event_id):
    event = db.get_or_404(AttackEvent, event_id)

    db.session.delete(event)
    db.session.commit()

    flash("Attack event deleted successfully!", "success")
    return redirect(url_for("events.list_events"))