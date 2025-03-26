
from app import db, bcrypt, app
from app.models import User

with app.app_context():  #when working outside of regular request handling
    if not User.query.filter_by(username='admin').first():
        hash_pswd = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password = hash_pswd, fullname = 'Admin User', is_admin = True)
        db.session.add(admin)
        db.session.commit()
        print("Admin created...")


'''
from app import app, db

with app.app_context():
    db.create_all()
    print("Database created...")

'''