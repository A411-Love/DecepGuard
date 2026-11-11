
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from app.extensions import db
from app.models import Alert, AttackEvent, Incident
from app.auth.permissions import role_required
from app.alerts.forms import AlertForm

alerts = Blueprint("alerts", __name__)


def prepare_form(form):
    events = AttackEvent.query.order_by(
        AttackEvent.timestamp.desc()
    ).all()

    incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    form.attack_event_id.choices = [
        (event.id, f"#{event.id} - {event.attack_type} - {event.source_ip}")
        for event in events
    ]

    form.incident_id.choices = [
        (0, "No linked incident")
    ] + [
        (incident.id, incident.title)
        for incident in incidents
    ]

    return events


@alerts.route("/")
@login_required
def list_alerts():
    all_alerts = Alert.query.order_by(
        Alert.created_at.desc()
    ).all()

    return render_template(
        "alerts/list.html",
        alerts=all_alerts
    )


@alerts.route("/add", methods=["GET", "POST"])
@role_required("admin", "analyst")
def add_alert():
    form = AlertForm()
    events = prepare_form(form)

    if not events:
        flash("Create an attack event before creating an alert.", "warning")
        return redirect(url_for("events.list_events"))

    if form.validate_on_submit():
        event_id = form.attack_event_id.data

        existing = Alert.query.filter_by(
            attack_event_id=event_id
        ).first()

        if existing:
            flash("An alert already exists for this attack event.", "warning")
            return redirect(url_for("alerts.list_alerts"))

        alert = Alert(
            attack_event_id=event_id,
            incident_id=form.incident_id.data or None,
            title=form.title.data.strip(),
            description=(form.description.data or "").strip(),
            severity=form.severity.data,
            status=form.status.data
        )

        db.session.add(alert)
        db.session.commit()

        flash("Alert created successfully!", "success")
        return redirect(url_for("alerts.list_alerts"))

    return render_template(
        "alerts/form.html",
        form=form,
        title="Create Alert"
    )


@alerts.route("/edit/<int:alert_id>", methods=["GET", "POST"])
@role_required("admin", "analyst")
def edit_alert(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    form = AlertForm(obj=alert)
    prepare_form(form)

    if form.validate_on_submit():
        alert.attack_event_id = form.attack_event_id.data
        alert.incident_id = form.incident_id.data or None
        alert.title = form.title.data.strip()
        alert.description = (form.description.data or "").strip()
        alert.severity = form.severity.data
        alert.status = form.status.data

        db.session.commit()

        flash("Alert updated successfully!", "success")
        return redirect(url_for("alerts.list_alerts"))

    if not form.is_submitted():
        form.incident_id.data = alert.incident_id or 0

    return render_template(
        "alerts/form.html",
        form=form,
        title="Edit Alert"
    )


@alerts.route("/delete/<int:alert_id>", methods=["POST"])
@role_required("admin", "analyst")
def delete_alert(alert_id):
    alert = db.get_or_404(Alert, alert_id)

    db.session.delete(alert)
    db.session.commit()

    flash("Alert deleted successfully!", "success")
    return redirect(url_for("alerts.list_alerts"))
