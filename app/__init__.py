from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate #track changes in the db models
from flask_bcrypt import Bcrypt   #hash and store encrypted pswd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/quizvista.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

from app import models