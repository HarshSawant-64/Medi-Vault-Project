from flask import Flask
from config import Config
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask_login import current_user
import os

# 1. IMPORT 'db' and 'login_manager' from models.py
# (Do NOT create a new SQLAlchemy(app) instance later!)
from models import db, login_manager 

# Get the directory where this script is located
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))

app = Flask(__name__, template_folder=template_dir)

# 2. CONFIGURATION
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://medivault_admin:galvin@localhost/medivault_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['SESSION_COOKIE_SECURE'] = False      # False for localhost (HTTP)
app.config['SESSION_COOKIE_HTTPONLY'] = True     
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None

# 3. INITIALIZE EXTENSIONS
# FIX: Use init_app(app) instead of creating a new db object
db.init_app(app)             
login_manager.init_app(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'

# 3.5 CONTEXT PROCESSOR - Make current_user available in all templates
@app.context_processor
def inject_user():
    return {'current_user': current_user}

# 4. SECURITY HEADERS
@app.after_request
def add_header(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
            
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# 5. IMPORT ROUTES (Must be at the bottom)
from routes import * # 6. START SERVER
if __name__ == '__main__':
    print("--- [SECURE] MEDIVAULT SYSTEM STARTING ---")
    
    # FIX: Create tables BEFORE running the app
    with app.app_context():
        db.create_all()
        print("[OK] Connected to MySQL and tables created!")

    print("--- SECURITY PROTOCOLS: ACTIVE ---")
    print("--- DEBUG MODE: DISABLED ---")
    
    # Use Waitress for a clean, warning-free production server
    # If you don't have waitress installed, run: pip install waitress
    try:
        from waitress import serve
        serve(app, host='127.0.0.1', port=5000)
    except ImportError:
        # Fallback if waitress is missing
        app.run(debug=False, port=5000)