from flask import render_template, request, redirect, url_for, flash, send_file, session
from app import app
from models import db, User, MedicalRecord, AuditLog, login_manager
from utils import SecureVault
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
import io
import hashlib
import re
from flask_wtf.csrf import CSRFError

vault = SecureVault()

# --- FILE SECURITY SETTINGS ---
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def is_safe_file(filename):
    # 1. Check extension presence
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    # 2. Block dangerous types explicitly
    if ext in ['html', 'htm', 'js', 'svg', 'php', 'exe', 'bat', 'sh']:
        return False
    # 3. Allow only specific types
    return ext in ALLOWED_EXTENSIONS

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
#              AUTH ROUTES
# ==========================================

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user:
            # 1. Check Lockout
            if user.lockout_until and user.lockout_until > datetime.utcnow():
                flash(f'Account Locked! Try again later.')
                
                # Log blocked attempt
                log = AuditLog(event="Login Blocked", user_ip=request.remote_addr, details=f"Locked user {username} tried to login")
                db.session.add(log)
                db.session.commit()
                return render_template('login.html')

            # 2. Check Password
            if check_password_hash(user.password_hash, password):
                # Success
                user.failed_attempts = 0
                user.lockout_until = None
                login_user(user)
                session.permanent = True # Enforce timeout config
                
                log = AuditLog(event="Login Success", user_ip=request.remote_addr, details=f"User {username} logged in")
                db.session.add(log)
                db.session.commit()
                return redirect(url_for('dashboard'))
            else:
                # Failure
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=5)
                    flash('Security Alert: 3 Failed Attempts. Account Locked.')
                    log = AuditLog(event="Account Locked", user_ip=request.remote_addr, details=f"User {username} triggered Brute Force Protection")
                else:
                    flash(f'Login Failed. Attempt {user.failed_attempts}/3')
                db.session.commit()
        else:
            flash('Login Failed. Check credentials.')
            
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    sec_question = request.form.get('sec_question')
    sec_answer = request.form.get('sec_answer')

    if User.query.filter_by(username=username).first():
        flash('Error: Username already exists!')
        return redirect(url_for('login'))

    # Password Policy
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[!@#$%^&*]", password):
        flash('Weak Password: Must be 8+ chars, include number & symbol.')
        return redirect(url_for('login'))

    normalized_answer = sec_answer.lower().strip()
    answer_hash = hashlib.sha256(normalized_answer.encode()).hexdigest()
    hashed_pw = generate_password_hash(password, method='scrypt')
    
    new_user = User(username=username, password_hash=hashed_pw, role=role, security_question=sec_question, security_answer_hash=answer_hash)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.')
    except Exception as e:
        db.session.rollback()
        flash('Database Error.')
        
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear() # Clear all permission slips
    return redirect(url_for('home'))

# ==========================================
#           DASHBOARD & UPLOAD
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'doctor':
        patients = User.query.filter_by(role='patient').all()
        return render_template('dashboard_doctor.html', patients=patients)
    else:
        files = MedicalRecord.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard_patient.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    entered_pin = request.form.get('auth_pin')

    # 1. Check Master PIN
    if not current_user.access_pin_hash:
        flash('Security Error: Setup a PIN first.')
        return redirect(url_for('dashboard'))
        
    entered_hash = hashlib.sha256(entered_pin.encode()).hexdigest()
    if entered_hash != current_user.access_pin_hash:
        flash('Upload Denied: Incorrect PIN.')
        log = AuditLog(event="Upload Blocked", user_ip=request.remote_addr, details=f"Failed PIN attempt during upload by {current_user.username}")
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('dashboard'))

    # 2. Magic Number Validation (Anti-Spoofing)
    filename = secure_filename(file.filename)
    
    # Read the first 4 bytes ("DNA" of the file)
    header = file.read(4) 
    
    # Reset cursor immediately so we don't save a corrupted file later
    file.seek(0)          
    
    is_valid_signature = False
    
    if filename.lower().endswith('.pdf') and header.startswith(b'%PDF'):
        is_valid_signature = True
    elif filename.lower().endswith('.png') and header.startswith(b'\x89PNG'):
        is_valid_signature = True
    elif filename.lower().endswith(('.jpg', '.jpeg')) and header.startswith(b'\xff\xd8\xff'):
        is_valid_signature = True
        
    if not is_valid_signature:
        flash('Security Alert: File spoofing detected! Content does not match extension.')
        log = AuditLog(event="Spoofing Attack", user_ip=request.remote_addr, details=f"User {current_user.username} tried upload fake {filename}")
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('dashboard'))
        
    if not is_safe_file(filename):
        flash('Invalid file type.')
        return redirect(url_for('dashboard'))

    # 3. Encrypt and Save
    file_data = file.read()
    encrypted_data = vault.encrypt_data(file_data)
    
    new_file = MedicalRecord(
        filename=filename,
        secure_filename=filename + ".enc",
        encrypted_data=encrypted_data,
        user_id=current_user.id
    )
    
    db.session.add(new_file)
    # Log the success
    log = AuditLog(event="File Upload", user_ip=request.remote_addr, details=f"User {current_user.username} uploaded {filename} (Authorized)")
    db.session.add(log)
    db.session.commit()
    
    flash('File Encrypted & Uploaded Successfully.')
    return redirect(url_for('dashboard'))

# ==========================================
#      NEW SECURE VIEWING LOGIC (3 STEPS)
# ==========================================

# STEP 1: Verify PIN & Grant "Permission Slip"
# routes.py

@app.route('/verify_view/<int:file_id>', methods=['POST'])
@login_required
def verify_view(file_id):
    
    record = MedicalRecord.query.get_or_404(file_id)
    entered_pin = request.form.get('pin_attempt')
    
    # 1. Check Authorization
    if current_user.id != record.user_id:
        if not (current_user.role == 'doctor' and session.get(f"unlocked_{record.user_id}")):
            flash('Unauthorized Access.')
            return redirect(url_for('dashboard'))

    # 2. Verify PIN
    entered_hash = hashlib.sha256(entered_pin.encode()).hexdigest()
    
    if entered_hash == current_user.access_pin_hash:
        # --- FIX: FORCE SAVE SESSION ---
        key = f'view_allowed_{file_id}'
        session[key] = True
        session.modified = True  # <--- CRITICAL FIX
        
        # Log it
        log = AuditLog(event="File Accessed", user_ip=request.remote_addr, details=f"User {current_user.username} unlocked file {record.filename}")
        db.session.add(log)
        db.session.commit()
        
        return redirect(url_for('view_page', file_id=file_id))
    else:
        flash('Access Denied: Incorrect PIN.')
        log = AuditLog(event="Access Denied", user_ip=request.remote_addr, details=f"User {current_user.username} failed PIN for {record.filename}")
        db.session.add(log)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
# STEP 2: Render the Wrapper Page (With Back Button)
@app.route('/secure_view/<int:file_id>')
@login_required
def view_page(file_id):
    key = f'view_allowed_{file_id}'
    # Security: Did they pass Step 1?
    if not session.get(f'view_allowed_{file_id}'):
        flash('Security Error: Illegal direct access.')
        return redirect(url_for('dashboard'))
        
    return render_template('viewer.html', file_id=file_id)

# STEP 3: Serve the Actual Content (Used by Iframe)
@app.route('/file_content/<int:file_id>')
@login_required
def get_file_content(file_id):
    # Double Security Check
    if not session.get(f'view_allowed_{file_id}'):
        return "Unauthorized", 403
        
    record = MedicalRecord.query.get_or_404(file_id)
    decrypted_data = vault.decrypt_data(record.encrypted_data)
    
    # Determine mimetype based on extension
    mime = 'application/octet-stream'
    if record.filename.lower().endswith('.pdf'): mime = 'application/pdf'
    elif record.filename.lower().endswith('.png'): mime = 'image/png'
    elif record.filename.lower().endswith(('.jpg', '.jpeg')): mime = 'image/jpeg'
    
    return send_file(io.BytesIO(decrypted_data), mimetype=mime)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = MedicalRecord.query.get_or_404(file_id)
    # Basic Authorization check
    if current_user.role != 'doctor' and current_user.id != file_record.user_id:
        return redirect(url_for('dashboard'))
        
    decrypted_data = vault.decrypt_data(file_record.encrypted_data)
    return send_file(io.BytesIO(decrypted_data), download_name=file_record.filename, as_attachment=True)

# ==========================================
#           OTHER UTILITIES
# ==========================================

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = MedicalRecord.query.get_or_404(file_id)
    
    # Only owner can delete
    if current_user.id != file_record.user_id:
        flash('Unauthorized.')
        return redirect(url_for('dashboard'))
        
    db.session.delete(file_record)
    db.session.commit()
    
    log = AuditLog(event="File Deleted", user_ip=request.remote_addr, details=f"User {current_user.username} deleted file {file_record.filename}")
    db.session.add(log)
    db.session.commit()
    
    flash('File deleted permanently.')
    return redirect(url_for('dashboard'))

@app.route('/set_pin', methods=['POST'])
@login_required
def set_pin():
    pin = request.form.get('pin')
    question = request.form.get('question') # Get the question
    answer = request.form.get('answer')
    if len(pin) != 4 or not pin.isdigit():
        flash('PIN must be exactly 4 digits.')
        return redirect(url_for('dashboard'))
    if not question or not answer:
        flash('Security Question and Answer are required.')
        return redirect(url_for('dashboard'))
    current_user.access_pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    current_user.security_question = question
    current_user.security_answer_hash = hashlib.sha256(answer.lower().strip().encode()).hexdigest()

    db.session.commit()
    flash('PIN Updated.')
    return redirect(url_for('dashboard'))

# DOCTOR: Unlock Patient
@app.route('/unlock_patient/<int:patient_id>', methods=['POST'])
@login_required
def unlock_patient(patient_id):
    if current_user.role != 'doctor': return redirect(url_for('dashboard'))
    
    target = User.query.get_or_404(patient_id)
    pin = request.form.get('pin_attempt')
    
    # Doctor enters PATIENT'S PIN to unlock the folder
    entered_hash = hashlib.sha256(pin.encode()).hexdigest()
    
    if entered_hash == target.access_pin_hash:
        session[f"unlocked_{patient_id}"] = True
        
        log = AuditLog(event="Vault Unlocked", user_ip=request.remote_addr, details=f"Doctor {current_user.username} unlocked Patient {target.username}")
        db.session.add(log)
        db.session.commit()
        
        flash(f'Unlocked records for {target.username}')
        return redirect(url_for('view_patient_files', patient_id=patient_id))
    else:
        flash('Incorrect Patient PIN.')
        log = AuditLog(event="Unauthorized Access", user_ip=request.remote_addr, details=f"Doctor {current_user.username} failed PIN for {target.username}")
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('dashboard'))

@app.route('/patient_files/<int:patient_id>')
@login_required
def view_patient_files(patient_id):
    if not session.get(f"unlocked_{patient_id}"):
        flash('Locked.')
        return redirect(url_for('dashboard'))
    files = MedicalRecord.query.filter_by(user_id=patient_id).all()
    patient = User.query.get(patient_id)
    return render_template('patient_files.html', patient=patient, files=files)

# ==========================================
#        SETTINGS & RECOVERY
# ==========================================

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_pass_input = request.form.get('current_password')
    new_pass = request.form.get('new_password')
    
    if not check_password_hash(current_user.password_hash, current_pass_input):
        flash('Security Alert: Incorrect Current Password.')
        return redirect(url_for('settings'))

    if len(new_pass) < 8 or not re.search(r"\d", new_pass) or not re.search(r"[!@#$%^&*]", new_pass):
        flash('Error: New password is too weak.')
        return redirect(url_for('settings'))
    
    current_user.password_hash = generate_password_hash(new_pass, method='scrypt')
    db.session.commit()
    flash('Success: Password updated securely.')
    return redirect(url_for('settings'))

@app.route('/update_pin', methods=['POST'])
@login_required
def update_pin():
    current_pass_input = request.form.get('current_password')
    new_pin = request.form.get('new_pin')
    
    if not check_password_hash(current_user.password_hash, current_pass_input):
        flash('Security Alert: Incorrect Password.')
        return redirect(url_for('settings'))
        
    if len(new_pin) != 4 or not new_pin.isdigit():
        flash('Error: PIN must be 4 digits.')
        return redirect(url_for('settings'))
        
    current_user.access_pin_hash = hashlib.sha256(new_pin.encode()).hexdigest()
    db.session.commit()
    flash('Success: Master PIN updated.')
    return redirect(url_for('settings'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username_check')
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('forgot_password.html', question=user.security_question, username=user.username)
        else:
            flash('User not found.')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', question=None)

@app.route('/reset_pin_request', methods=['GET', 'POST'])
@login_required
def reset_pin_request():
    # If they haven't set up security yet, kick them back
    if not current_user.security_question:
        flash('No security question set. Cannot reset PIN.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entered_answer = request.form.get('answer')
        new_pin = request.form.get('new_pin')
        
        # Check Answer
        entered_hash = hashlib.sha256(entered_answer.lower().strip().encode()).hexdigest()
        
        if entered_hash == current_user.security_answer_hash:
            # Success! Update PIN
            if len(new_pin) == 4 and new_pin.isdigit():
                current_user.access_pin_hash = hashlib.sha256(new_pin.encode()).hexdigest()
                db.session.commit()
                flash('Success! Your PIN has been reset.')
                return redirect(url_for('dashboard'))
            else:
                flash('New PIN must be 4 digits.')
        else:
            flash('Incorrect Security Answer.')
            
    return render_template('reset_pin.html')

@app.route('/reset_with_token', methods=['POST'])
def reset_with_token():
    username = request.form.get('username')
    answer_input = request.form.get('answer_attempt')
    new_password = request.form.get('new_password')
    
    user = User.query.filter_by(username=username).first()
    normalized_input = answer_input.lower().strip()
    input_hash = hashlib.sha256(normalized_input.encode()).hexdigest()
    
    if user and input_hash == user.security_answer_hash:
        if len(new_password) < 8:
            flash('Password too weak.')
            return redirect(url_for('login'))
            
        user.password_hash = generate_password_hash(new_password, method='scrypt')
        user.failed_attempts = 0
        user.lockout_until = None
        
        log = AuditLog(event="Account Recovery", user_ip=request.remote_addr, details=f"User {username} reset password")
        db.session.add(log)
        db.session.commit()
        
        flash('Success! Password reset. Please Login.')
        return redirect(url_for('login'))
    else:
        flash('Security Alert: Wrong Answer.')
        log = AuditLog(event="Recovery Failed", user_ip=request.remote_addr, details=f"Failed recovery attempt for {username}")
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('login'))

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('login.html', error="Session expired (CSRF). Please login again."), 400