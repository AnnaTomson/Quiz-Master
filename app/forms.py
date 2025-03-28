from flask_wtf import FlaskForm
from wtforms import SpringField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired

class SubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Save')

class ChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    sub_id = SelectField('Subject', coerce=int)
    submit = SubmitField('Save')