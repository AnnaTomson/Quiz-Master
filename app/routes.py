from app import app, db, bcrypt
from flask import render_template, redirect, flash, url_for, request
from app.models import User, Subject, Chapter
from app.forms import SubjectForm, ChapterForm
from flask_login import login_user, logout_user, login_required, LoginManager

login_manager = LoginManager(app)
login_manager.login_view = 'admin_login' #to specify route for unauthenticated users

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Admin login & Home page

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin/login', methods = ['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form('username')
        password = request.form('password')
        user = User.query.filter_by(username=username, is_admin = True).first()

        if user and user.is_admin and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Welcome Admin!!!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        else:
            flash('Invalid details! Please Try Again', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

#creating admin dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorised Access!', 'danger')
        return redirect(url_for('admin_login'))
    return render_template('admin/dashboard.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You\'ve been logged out...', 'success')
    return redirect(url_for('admin_login'))


# MANAGING SUBJECT

@app.route('/admin/subjects')
@login_required
def view_subjects():
    subjects = Subject.query.all()
    return render_template('view_subjects.html', subjects=subjects)

#create new subject
@app.route('/admin/subjects/new', methods=['GET', 'POST'])
@login_required
def create_subject(id):
    subject = Subject.query.get_or_404(id)
    form = SubjectForm(obj=subject)
    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data
        db.session.commit()
        flash('Subject updated successfully!!!', 'success')
        return redirect(url_for('view_subjects'))
    return render_template('create_subject.html', form=form)

#edit subject
@app.route('/admin/subjects/edit/<int:sub_id>', methods=['GET', 'POST'])
@login_required
def edit_subject(id):
    subject = Subject.query.get_or_404(id)
    form = SubjectForm(obj=subject)
    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data
        db.session.commit()
        flash('Updated subject successfully!!!', 'success')
        return redirect(url_for('view_subjects'))
    return render_template('create_subject.html', form=form)


#delete subject
@app.route('/admin/subjects/delete/<int:id>', methods=['POST'])
@login_required
def delete_subject(id):
    subject = Subject.query.get_or_404(id)
    db.session.delete(subject)
    de.session.commit()
    flash('Subject deleted successfully!!!', 'success')
    return redirect(url_for('vew_subjects'))


# MANAGING CHAPTERS
@app.route('/admin/chapters/<int:sub_id>')
@login_required
def view_chapters(sub_id):
    subject = Subject.query.get_or_404(sub_id)
    chapters = Chapter.query.filter_by(sub_id=sub_id).all()
    return render_template('view_chapters.html', chapters=chapters, subject=subject)

# create chapter
@app.route('/admin/chapters/new/<int:sub_id>', methods=['GET', 'POST'])
@login_required
def create_chapter(sub_id):
    form = ChapterForm()
    form.sub_id.data = sub_id
    if form.validate_on_submit():
        chapter = Chapter(name=form.name.data, description = form.description.data, sub_id = sub_id)
        db.session.add(chapter)
        db.session.commit()
        flash('Created chapter successfully!!!', 'success')
        return redirect(url_for('view_chapters', sub_id= sub_id))
    return render_template('create_chapter.html', form=form)


# edit chapter
@app.route('/admin/chapters/edit/<int:sub_id>', methods=['GET', 'POST'])
@login_required
def edit_chapter(sub_id):
    chapter = Chapter.query.get_or_404(id)
    form = ChapterForm(obj=chapter)
    if form.validate_on_submit():
        chapter.name = form.name.data
        chapter.description = form.description.data
        db.session.commit()
        flash('Updated chapter successfully!!!', 'success')
        return redirect(url_for('view_chapters', sub_id= chapter.sub_id))
    return render_template('create_chapter.html', form=form)


# delete chapter
@app.route('/admin/chapters/delete/<int:id>', methods=['POST'])
@login_required
def delete_chapter(id):
    chapter = Chapter.query.get_or_404(id)
    sub_id = chapter.sub_id
    db.session.delete(chapter)
    de.session.commit()
    flash('Deleted Chapter successfully!!!', 'success')
    return redirect(url_for('vew_chapters', sub_id=sub_id))


#REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method=='POST':
        username = request.form['username']
        email=request.form['email']
        fullname = request.form['fullname']
        qualification = request.form['qualification']
        dob = request.form['dob']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Try Again!', 'danger')
            return redirect(url_for('register'))

        elif User.query.filter_by(username=username).first():
            flash('Username already exists. Try a different one!', 'danger')
            return redirect(url_for('register'))
        
        elif User.query.filter_by(email=email).first():
            flash('Email is already registered! Please login', 'warning')
            return redirect(url_for('user_login'))

        else:
            hash_pswd = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hash_pswd, fullname=fullname, dob=dob, qualification=qualification)

            db.session.add(new_user)
            db.session.commit()

            flash('Registered successfully! Please Log in!!!', 'success')
            return redirect(url_for('user_login'))

    return render_template('register.html')


#user login
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('user_login.html')