
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional, Length


class IncidentForm(FlaskForm):
    title = StringField(
        "Incident Title",
        validators=[DataRequired(), Length(max=150)]
    )

    description = TextAreaField(
        "Description",
        validators=[Optional(), Length(max=3000)]
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
            ("Open", "Open"),
            ("In Progress", "In Progress"),
            ("Contained", "Contained"),
            ("Resolved", "Resolved"),
            ("Closed", "Closed")
        ],
        validators=[DataRequired()]
    )

    assigned_to = SelectField(
        "Assign Analyst",
        coerce=int,
        validators=[Optional()]
    )

    resolution_notes = TextAreaField(
        "Resolution Notes",
        validators=[Optional(), Length(max=3000)]
    )

    submit = SubmitField("Save Incident")
