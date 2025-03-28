from app import db
from datetime import datetime
from flask_login import UserMixin  #for user authentication and sessions
'''from flask_login import LoginManager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))'''

class User(db.Model, UserMixin):
    __tablename__ = 'user' 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(100))
    dob = db.Column(db.Date)
    is_admin = db.Column(db.Boolean, default=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), unique = True, nullable = False)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref = 'subject', lazy = True)  #lazy=True => lazy='select' (how SQLAlchemy should load the related objects)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    description = db.Column(db.Text)
    sub_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable = False)
    quizes = db.relationship('Quiz', backref = 'chapter', lazy=True)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable = False)
    date_of_quiz = db.Column(db.Date)
    time_duration = db.Column(db.Integer)  #hh:mm
    remarks = db.Column(db.Text)
    questions = db.relationship('Questions', backref = 'quiz', lazy = True)

class Questions(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable = False)
    question_statement = db.Column(db.Text, nullable = False)
    option1 = db.Column(db.String(100))
    option2 = db.Column(db.String(100))
    option3 = db.Column(db.String(100))
    option4 = db.Column(db.String(100))
    correct_option = db.Column(db.String(1))

class Scores(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    time_stamp_of_attempt = db.Column(db.DateTime, default = datetime.utcnow)
    total_scored = db.Column(db.Integer)