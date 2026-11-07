from flask import Blueprint, render_template, redirect, url_for, flash
from app.extensions import db
from app.models import User
from app.auth.forms import RegistrationForm


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