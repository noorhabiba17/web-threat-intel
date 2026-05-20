import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional

PWD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$")
def strong_pw(form, field):
    if not PWD_RE.match(field.data or ""):
        raise ValidationError("Password must be 8+ chars with uppercase, lowercase, digit and symbol.")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3,64)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), strong_pw])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    security_question = SelectField("Security Question", choices=[
        ("pet","What is the name of your first pet?"),
        ("city","In which city were you born?"),
        ("school","What was the name of your first school?"),
    ])
    security_answer = StringField("Answer", validators=[DataRequired(), Length(min=2, max=120)])
    submit = SubmitField("Create account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class ForgotForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    security_answer = StringField("Security Answer", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), strong_pw])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("new_password")])
    submit = SubmitField("Reset password")

class ScanForm(FlaskForm):
    scan_type = SelectField("Type", choices=[("url","URL"),("email","Email"),("sms","SMS / Message")])
    payload = TextAreaField("Content", validators=[DataRequired(), Length(min=3, max=10000)])
    description = StringField("Note (optional)", validators=[Optional(), Length(max=255)])
    submit = SubmitField("Scan now")
