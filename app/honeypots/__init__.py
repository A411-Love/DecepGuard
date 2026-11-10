from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from app.extensions import db
from app.models import Honeypot
from app.auth.permissions import role_required
from app.honeypots.forms import HoneypotForm

honeypots = Blueprint("honeypots", __name__)


@honeypots.route("/")
@login_required
def list_honeypots():
    all_honeypots = Honeypot.query.order_by(
        Honeypot.created_at.desc()
    ).all()

    return render_template(
        "honeypots/list.html",
        honeypots=all_honeypots
    )


@honeypots.route("/add", methods=["GET", "POST"])
@role_required("admin", "analyst")
def add_honeypot():
    form = HoneypotForm()

    if form.validate_on_submit():
        honeypot = Honeypot(
            name=form.name.data.strip(),
            honeypot_type=form.honeypot_type.data,
            ip_address=form.ip_address.data.strip(),
            port=form.port.data,
            description=form.description.data,
            status=form.status.data
        )

        db.session.add(honeypot)
        db.session.commit()

        flash("Honeypot created successfully!", "success")
        return redirect(url_for("honeypots.list_honeypots"))

    return render_template("honeypots/add.html", form=form)