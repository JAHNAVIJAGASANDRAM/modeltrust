"""Auth WTForms."""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from sqlalchemy import func
from app.models.user import User


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=64)],
        render_kw={"placeholder": "Choose a username"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "your@email.com"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
        render_kw={"placeholder": "8–128 characters"},
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
        render_kw={"placeholder": "Repeat password"},
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        field.data = field.data.strip()
        if User.query.filter(func.lower(User.username) == field.data.lower()).first():
            raise ValidationError("Username already taken.")

    def validate_email(self, field):
        field.data = field.data.strip().lower()
        if User.query.filter(func.lower(User.email) == field.data).first():
            raise ValidationError("Email already registered.")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "your@email.com"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
        render_kw={"placeholder": "Password"},
    )
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign In")
