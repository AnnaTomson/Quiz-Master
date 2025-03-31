# Quiz Master 

## Overview
Quiz Master is a multi-user exam preparation platform. It allows users to take quizzes based on subjects and chapters, while admins can manage quizzes and monitor results.

## Key Features
**Admin Features:**
- Create and manage subjects and chapters
- Add quizzes and questions with multiple choices
- Edit or delete quizzes
- View user quiz results

**User Features:**
- View and take available quizzes
- Submit answers and view scores
- Track quiz history
Technologies Used
- Flask (Backend)
- SQLite (Database)
- SQLAlchemy (ORM)
- Jinja2 (Templating)
- Bootstrap (UI Styling)
- Flask-Login and Flask-Bcrypt (Authentication)

## Setup and Installation
1. **Clone the Repository:**
   
```bash 
git clone https://github.com/your-repo/quiz-master.git
cd quiz-master
```

3. **Create Virtual Environment:**
```bash
python3 -m venv venv
source venv/bin/activate
```
3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```
4. **Setup Database:**
```bash
flask db init
flask db migrate
flask db upgrade
```
5. **Run the Application:**
```bash
flask run
```
6. **Access the App:**

Open `http://127.0.0.1:5000` in your browser.

## Database Design
- **User Table:** Stores user details and roles (Admin/User).
- **Subject Table:** Contains subject names and descriptions.
- **Chapter Table:** Stores chapters under specific subjects.
- **Quiz Table:** Holds quiz details like date, duration, and remarks.
- **Questions Table:** Contains multiple-choice questions with four options.
- **Quiz Result Table:** Records users' quiz attempts, scores, and attempt dates.

## API Endpoints
- `/admin/login` → Admin Login
- `/admin/dashboard` → Admin Dashboard
- `/admin/quiz/add` → Add New Quiz
- `/admin/question/add` → Add Questions to Quiz
- `/user/login` → User Login
- `/user/dashboard` → User Dashboard
- `/start_quiz/<quiz_id>` → Start Quiz
- `/submit_quiz/<quiz_id>` → Submit Quiz and Calculate Score
- `/view_result/<quiz_id>` → View Quiz Result

