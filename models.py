from sqlalchemy.dialects.mysql import LONGBLOB 
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from datetime import datetime

# 1. Initialize extensions (Unbound)
db = SQLAlchemy()
login_manager = LoginManager() 

# 2. CRITICAL: The User Loader Function
# Flask-Login needs this to find the user ID in the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 3. Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    access_pin_hash = db.Column(db.String(128), nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    security_question = db.Column(db.String(255), nullable=True)
    security_answer_hash = db.Column(db.String(256), nullable=True)

class MedicalRecord(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    secure_filename = db.Column(db.String(255), nullable=False)
    encrypted_data = db.Column(LONGBLOB, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100))
    user_ip = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255))