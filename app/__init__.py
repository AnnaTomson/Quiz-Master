from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate #track changes in the db models
from flask_bcrypt import Bcrypt   #hash and store encrypted pswd
from flask_login import LoginManager
#import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/quizvista.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_viw = 'user_login'
login_manager.login_message_category = 'info'

from app import routes, models