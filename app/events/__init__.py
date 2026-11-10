from flask import (
    Blueprint, render_template, redirect,
    url_for, flash, request
)

from flask_login import login_required

from app.extensions import db
from app.models import AttackEvent, Honeypot
from app.auth.permissions import role_required
from app.events.forms import AttackEventForm


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
            description=form.description.data.strip(),
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
        event.description = form.description.data.strip()

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