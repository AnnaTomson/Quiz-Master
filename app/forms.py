from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, SelectField, PasswordField, DateField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
from app.models import User

class SubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Save')

class ChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    sub_id = SelectField('Subject', coerce=int)
    submit = SubmitField('Save')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=3, max=50)])
    dob = DateField('Date of Birth (YYYY-MM-DD)', validators=[DataRequired()], format='%Y-%m-%d')
    qualification = StringField('Qualification', validators=[DataRequired(), Length(min=2, max=100)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose another one...')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered...')
