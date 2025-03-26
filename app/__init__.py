from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET KEY'] = 'mysecretkey'

app.config['SQLALCHEMY_DARABASE_URI'] = 'sql'