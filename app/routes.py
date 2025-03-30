from app import app, db, bcrypt
from flask import render_template, redirect, flash, url_for, request, session
from app.models import User, Subject, Chapter, Quiz
from app.forms import SubjectForm, ChapterForm, RegistrationForm
from flask_login import login_user, logout_user, login_required, LoginManager, current_user
from flask_bcrypt import Bcrypt

login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
login_manager.login_view = 'admin_login' #to specify route for unauthenticated users
login_manager.login_message_category='danger'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Admin login & Home page

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/login', methods = ['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = User.query.filter_by(username=username, is_admin = True).first()

        if admin and bcrypt.check_password_hash(admin.password, password):
            login_user(admin)
            flash('Welcome Admin!!!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        else:
            flash('Invalid details! Please Try Again', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

#admin dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorised Access!', 'danger')
        return redirect(url_for('admin_login'))

    subjects = Subject.query.all()
    total_subjects = Subject.query.count()
    total_chapters = Chapter.query.count()
    total_quizzes = Quiz.query.count()
    total_users = User.query.count()
    return render_template('admin_dashboard.html', subjects=subjects, total_subjects=total_subjects, total_chapters=total_chapters, total_quizzes=total_quizzes, total_users=total_users)



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
        return redirect(url_for('admin_dashboard'))

#edit subject
@app.route('/admin/subjects/edit/<int:sub_id>', methods=['GET', 'POST'])
@login_required
def edit_subject(sub_id):
    subject = Subject.query.get_or_404(sub_id)
    subject.name = request.form.get('name')
    subject.description = request.form.get('description')
    db.session.commit()
    flash('Subject updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

#delete subject
@app.route('/admin/subjects/delete/<int:sub_id>', methods=['POST'])
@login_required
def delete_subject(sub_id):
    subject = Subject.query.get_or_404(sub_id)

    try:
        db.session.delete(subject)
        db.session.commit()
        flash('Subject deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {e}', 'error')

    return redirect(url_for('admin_dashboard'))


# MANAGING CHAPTERS
@app.route('/admin/chapters/<int:sub_id>')
@login_required
def view_chapters(sub_id):
    subject = Subject.query.get_or_404(sub_id)
    chapters = Chapter.query.filter_by(sub_id=sub_id).all()
    return render_template('view_chapters.html', chapters=chapters, subject=subject)

# add chapter
@app.route('/admin/chapter/new/<int:sub_id>', methods=['GET', 'POST'])
@login_required
def add_chapter(sub_id):
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        flash('Chapter name is required.', 'error')
        return redirect(url_for('admin_dashboard'))

    new_chapter = Chapter(name=name, description=description, sub_id=sub_id)
    db.session.add(new_chapter)
    db.session.commit()

    flash('Chapter added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))



# edit chapter
@app.route('/admin/chapter/edit/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def edit_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    if request.method == 'POST':
        chapter.name = request.form['name']
        chapter.description = request.form['description']
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
        return redirect(url_for('quiz_management'))
    return render_template('edit_chapter.html', chapter=chapter)


# delete chapter
@app.route('/admin/chapter/delete/<int:chapter_id>', methods=['POST'])
@login_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    db.session.delete(chapter)
    db.session.commit()
    flash('Chapter deleted successfully!', 'success')
    return redirect(url_for('quiz_management'))


#REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_pswd = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hash_pswd,
            fullname=form.fullname.data,
            dob=form.dob.data,
            qualification=form.qualification.data
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Registered successfully! Please Log in!!!', 'success')
        return redirect(url_for('user_login'))

    return render_template('register.html', form=form)


#user login
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is None:
            flash('User not registered. Please register first.', 'danger')
            return redirect(url_for('user_login'))

        if bcrypt.check_password_hash(user.password, password):
            session['user_logged_in'] = True
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))

        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('user_login'))
    return render_template('user_login.html')


#manage users
@app.route('/admin/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Unauthorized Access!', 'danger')
        return redirect(url_for('admin_login'))

    users = User.query.all()
    return render_template('admin/view_users.html', users=users)


#add subject
@app.route('/admin/add-subject', methods=['POST'])
def add_subject():
    name = request.form.get('name')
    description = request.form.get('description')
    #chapter_count = int(request.form.get('chapter_count'))
    #Subject.append({"name": name, "chapter_count": chapter_count})
    new_subject = Subject(name=name)
    db.session.add(new_subject)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


#logout
@app.route('/logout')
def logout():
    return redirect(url_for('admin_login'))

#quiz management
@app.route('/quiz-management')
def quiz_management():
    subjects = Subject.query.all()
    return render_template('quiz_management.html', subjects=subjects)


#add quiz
@app.route('/add_quiz', methods=['GET', 'POST'])
@login_required
def add_quiz():
    if request.method == 'POST':
        try:
            chapter_id = request.form.get('chapter_id')
            date_of_quiz = request.form.get('date_of_quiz')
            time_duration = request.form.get('time_duration')
            remarks = request.form.get('remarks', '')

            # Validate inputs
            if not (chapter_id and date_of_quiz and time_duration):
                flash('Please fill out all fields.', 'danger')
                return redirect(url_for('quiz_management'))

            # Convert date to the correct format
            date_of_quiz = datetime.strptime(date_of_quiz, '%Y-%m-%d').date()
            time_duration = int(time_duration)

            # Verify Chapter exists
            chapter = Chapter.query.get(chapter_id)
            if not chapter:
                flash('Invalid chapter selection.', 'danger')
                return redirect(url_for('quiz_management'))

            # Create and store the quiz
            new_quiz = Quiz(
                chapter_id=chapter_id,
                date_of_quiz=date_of_quiz,
                time_duration=time_duration,
                remarks=remarks
            )

            db.session.add(new_quiz)
            db.session.commit()
            flash('Quiz added successfully!', 'success')
            return redirect(url_for('quiz_management'))

        except ValueError as e:
            flash(f'Invalid input: {e}', 'danger')
        except Exception as e:
            flash(f'Error occurred: {e}', 'danger')

    # Load chapters for selection in the form
    chapters = Chapter.query.all()
    return render_template('add_quiz.html', chapters=chapters)


#edit quiz
@app.route('/edit-quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        quiz.date_of_quiz = request.form.get('date_of_quiz')
        quiz.time_duration = int(request.form.get('time_duration'))
        quiz.remarks = request.form.get('remarks')

        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('quiz_management'))

    return render_template('edit_quiz.html', quiz=quiz)


#delete quiz
@app.route('/delete-quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!', 'success')
    return redirect(url_for('quiz_management'))


#user dashboard
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    quizzes = db.session.query(Quiz, Chapter).join(Chapter).all()
    return render_template('user_dashboard.html', quizzes=quizzes)


#my quizzes
@app.route('/my_quizzes')
@login_required
def my_quizzes():
    quizzes = Quiz.query.join(Chapter).join(Subject).all()
    return render_template('my_quizzes.html', quizzes=quizzes)



#profile
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


#edit profile
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']

        if User.query.filter(User.username == new_username, User.id != current_user.id).first():
            flash('Username already taken. Choose a different one.', 'danger')
        elif User.query.filter(User.email == new_email, User.id != current_user.id).first():
            flash('Email already registered. Use a different email.', 'danger')
        else:
            current_user.username = new_username
            current_user.email = new_email
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)


#logout
@app.route('/user_logout')
def user_logout():
    session.clear()
    return redirect(url_for('user_login'))


#start quiz
@app.route('/start_quiz/<int:quiz_id>', methods=['GET'])
def start_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('start_quiz.html', quiz=quiz)





