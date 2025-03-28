from app import app, db, bcrypt
from flask import render_template, redirect, flash, url_for, request
from app.models import User
from flask_login import login_user, logout_user, login_required, LoginManager

login_manager = LoginManager(app)
login_manager.login_view = 'admin_login' #to specify route for unauthenticated users

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    return render_template('user/login.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin-login', methods = ['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form('username')
        password = request.form('password')
        user = User.query.filter_by(username=username, is_admin = True).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Welcome Admin!!!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        else:
            flash('Invalid details! Please Try Again', 'danger')
    return render_template('admin/login.html')

#creating admin dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

def admin_logout():
    logout_user()
    flash('You\'ve been logged out...', 'success')
    return redirect(url_for('admin_login'))
