from flask import Blueprint, render_template, redirect, url_for, flash
from app.extensions import db
from app.models import User
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

    return render_template("dashboard.html")