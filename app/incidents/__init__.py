
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from app.extensions import db
from app.models import Incident, User
from app.auth.permissions import role_required
from app.incidents.forms import IncidentForm

incidents = Blueprint("incidents", __name__)


def prepare_form(form):
    analysts = User.query.filter(
        User.role.in_(["admin", "analyst"]),
        User.is_active.is_(True)
    ).order_by(User.username).all()

    form.assigned_to.choices = [
        (0, "Unassigned")
    ] + [
        (user.id, user.username)
        for user in analysts
    ]


@incidents.route("/")
@login_required
def list_incidents():
    all_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    return render_template(
        "incidents/list.html",
        incidents=all_incidents
    )


@incidents.route("/add", methods=["GET", "POST"])
@role_required("admin", "analyst")
def add_incident():
    form = IncidentForm()
    prepare_form(form)

    if form.validate_on_submit():
        incident = Incident(
            title=form.title.data.strip(),
            description=(form.description.data or "").strip(),
            severity=form.severity.data,
            status=form.status.data,
            assigned_to=form.assigned_to.data or None,
            resolution_notes=(form.resolution_notes.data or "").strip()
        )

        db.session.add(incident)
        db.session.commit()

        flash("Incident created successfully!", "success")
        return redirect(url_for("incidents.list_incidents"))

    return render_template(
        "incidents/form.html",
        form=form,
        title="Create Incident"
    )


@incidents.route("/edit/<int:incident_id>", methods=["GET", "POST"])
@role_required("admin", "analyst")
def edit_incident(incident_id):
    incident = db.get_or_404(Incident, incident_id)
    form = IncidentForm(obj=incident)
    prepare_form(form)

    if form.validate_on_submit():
        incident.title = form.title.data.strip()
        incident.description = (form.description.data or "").strip()
        incident.severity = form.severity.data
        incident.status = form.status.data
        incident.assigned_to = form.assigned_to.data or None
        incident.resolution_notes = (
            form.resolution_notes.data or ""
        ).strip()

        db.session.commit()

        flash("Incident updated successfully!", "success")
        return redirect(url_for("incidents.list_incidents"))

    if not form.is_submitted():
        form.assigned_to.data = incident.assigned_to or 0

    return render_template(
        "incidents/form.html",
        form=form,
        title="Edit Incident"
    )


@incidents.route("/delete/<int:incident_id>", methods=["POST"])
@role_required("admin")
def delete_incident(incident_id):
    incident = db.get_or_404(Incident, incident_id)

    # Keep associated alerts, but remove their incident link.
    for alert in incident.alerts:
        alert.incident_id = None

    db.session.delete(incident)
    db.session.commit()

    flash("Incident deleted successfully!", "success")
    return redirect(url_for("incidents.list_incidents"))
