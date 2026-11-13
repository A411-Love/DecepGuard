from flask import Blueprint, render_template, redirect, url_for, flash
from app.extensions import db
from app.models import User, Honeypot, AttackEvent, Alert, Incident
from app.auth.forms import RegistrationForm
from flask_login import login_user, logout_user, login_required, current_user
from app.auth.forms import LoginForm

auth = Blueprint("auth", __name__)


@auth.route("/register", methods=["GET", "POST"])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            flash("Username or email already exists.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(
            username=form.username.data,
            email=form.email.data,
            role="viewer"
        )

        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! You can log in soon.", "success")

        return redirect(url_for("home"))

    return render_template("auth/register.html", form=form)




@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    form = LoginForm()

    if form.validate_on_submit():

        user = User.query.filter_by(
            email=form.email.data
        ).first()

        if user and user.is_active and user.check_password(form.password.data):

            login_user(user)

            flash("Login successful. Welcome to DecepGuard!", "success")

            return redirect(url_for("auth.dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash("You have been logged out.", "success")

    return redirect(url_for("auth.login"))


@auth.route("/dashboard")
@login_required
def dashboard():

    # Honeypot statistics
    total_honeypots = Honeypot.query.count()
    active_honeypots = Honeypot.query.filter_by(
        status="active"
    ).count()

    # Attack event statistics
    total_events = AttackEvent.query.count()

    # Separate simulated and Cowrie events
    simulated_events = AttackEvent.query.filter_by(
        event_source="simulated"
    ).count()

    cowrie_events = AttackEvent.query.filter_by(
        event_source="cowrie"
    ).count()

    recent_events = AttackEvent.query.order_by(
        AttackEvent.timestamp.desc()
    ).limit(5).all()

    # Alert statistics
    total_alerts = Alert.query.count()

    # Count incidents that still require attention
    open_incidents = Incident.query.filter(
        Incident.status.notin_(["Resolved", "Closed"])
    ).count()

    # Count events according to severity
    severity_counts = {
        "Low": AttackEvent.query.filter_by(severity="Low").count(),
        "Medium": AttackEvent.query.filter_by(severity="Medium").count(),
        "High": AttackEvent.query.filter_by(severity="High").count(),
        "Critical": AttackEvent.query.filter_by(severity="Critical").count()
    }

    return render_template(
        "dashboard.html",
        simulated_events=simulated_events,
        cowrie_events=cowrie_events,
        total_honeypots=total_honeypots,
        active_honeypots=active_honeypots,
        total_events=total_events,
        total_alerts=total_alerts,
        open_incidents=open_incidents,
        recent_events=recent_events,
        severity_counts=severity_counts
    )