from app import app, db, bcrypt
from flask import render_template, redirect, flash, url_for, request
from app.models import User
from flask_login import login_user, logout_user, login_required, LoginManager

login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'