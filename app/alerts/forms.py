
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional, Length


class AlertForm(FlaskForm):
    attack_event_id = SelectField(
        "Attack Event",
        coerce=int,
        validators=[DataRequired()]
    )

    incident_id = SelectField(
        "Linked Incident",
        coerce=int,
        validators=[Optional()]
    )

    title = StringField(
        "Alert Title",
        validators=[DataRequired(), Length(max=150)]
    )

    description = TextAreaField(
        "Description",
        validators=[Optional(), Length(max=2000)]
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

    status = SelectField(
        "Status",
        choices=[
            ("New", "New"),
            ("Acknowledged", "Acknowledged"),
            ("Investigating", "Investigating"),
            ("Resolved", "Resolved")
        ],
        validators=[DataRequired()]
    )

    submit = SubmitField("Save Alert")
