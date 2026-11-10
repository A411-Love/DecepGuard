from flask_wtf import FlaskForm
from wtforms import (
    SelectField,
    StringField,
    IntegerField,
    TextAreaField,
    SubmitField
)
from wtforms.validators import (
    DataRequired,
    Optional,
    Length,
    NumberRange,
    IPAddress
)


class AttackEventForm(FlaskForm):

    honeypot_id = SelectField(
        "Honeypot",
        coerce=int,
        validators=[DataRequired()]
    )

    source_ip = StringField(
        "Source IP Address",
        validators=[
            DataRequired(),
            IPAddress(ipv4=True, ipv6=True)
        ]
    )

    source_port = IntegerField(
        "Source Port",
        validators=[
            Optional(),
            NumberRange(min=1, max=65535)
        ]
    )

    destination_port = IntegerField(
        "Destination Port",
        validators=[
            DataRequired(),
            NumberRange(min=1, max=65535)
        ]
    )

    protocol = SelectField(
        "Protocol",
        choices=[
            ("TCP", "TCP"),
            ("UDP", "UDP"),
            ("HTTP", "HTTP"),
            ("HTTPS", "HTTPS"),
            ("SSH", "SSH")
        ],
        validators=[DataRequired()]
    )

    attack_type = SelectField(
        "Attack Type",
        choices=[
            ("SSH Login Attempt", "SSH Login Attempt"),
            ("Brute Force Attempt", "Brute Force Attempt"),
            ("Port Scanning", "Port Scanning"),
            ("Suspicious HTTP Request", "Suspicious HTTP Request"),
            ("Unauthorized Access Attempt", "Unauthorized Access Attempt"),
            ("Other", "Other")
        ],
        validators=[DataRequired()]
    )

    severity = SelectField(
        "Severity",
        choices=[
            ("Low", "Low"),
            ("Medium", "Medium"),
            ("High", "High"),
            ("Critical", "Critical")
        ],
        validators=[DataRequired()]
    )

    description = TextAreaField(
        "Description",
        validators=[Optional(), Length(max=2000)]
    )

    submit = SubmitField("Save Event")