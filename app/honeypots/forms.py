
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    IntegerField,
    SelectField,
    TextAreaField,
    SubmitField
)
from wtforms.validators import (
    DataRequired,
    Length,
    NumberRange
)


class HoneypotForm(FlaskForm):

    name = StringField(
        "Honeypot Name",
        validators=[
            DataRequired(),
            Length(min=3, max=100)
        ]
    )

    honeypot_type = SelectField(
        "Honeypot Type",
        choices=[
            ("SSH", "SSH"),
            ("HTTP", "HTTP"),
            ("FTP", "FTP"),
            ("Telnet", "Telnet"),
            ("Database", "Database")
        ],
        validators=[DataRequired()]
    )

    ip_address = StringField(
        "IP Address",
        validators=[
            DataRequired(),
            Length(max=45)
        ]
    )

    port = IntegerField(
        "Port",
        validators=[
            DataRequired(),
            NumberRange(min=1, max=65535)
        ]
    )

    description = TextAreaField(
        "Description",
        validators=[Length(max=1000)]
    )

    status = SelectField(
        "Status",
        choices=[
            ("active", "Active"),
            ("inactive", "Inactive"),
            ("maintenance", "Maintenance")
        ],
        validators=[DataRequired()]
    )

    submit = SubmitField("Save Honeypot")
