import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Certificate, Email
import crypto


app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
app.secret_key = 'super_secret_key_for_dev_only'

# Configure SQLite Database
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'signet.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# --- FIX 1: Replace deprecated @app.before_first_request ---
# Initialize DB tables and CA when the app starts
with app.app_context():
    db.create_all()
    crypto.init_ca()

# Helper to verify an email's signature dynamically
def verify_email_signature(email_obj):
    sender = User.query.filter_by(email=email_obj.sender_email).first()
    if not sender:
        return False, "Sender is not registered in SigNet. Certificate untrusted."
    
    cert_rec = Certificate.query.filter_by(user_id=sender.id, is_active=True).first()
    if not cert_rec:
        return False, "Sender has no active cryptographic credentials."
    
    # Format payload exactly as it was signed
    payload = crypto.get_message_payload(
        email_obj.sender_email,
        email_obj.recipient_email,
        email_obj.subject,
        email_obj.body,
        email_obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    )
    
    verified, msg = crypto.verify_message_signature(
        cert_rec.certificate_pem,
        payload,
        email_obj.signature
    )
    return verified, msg

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Middleware equivalent to check authentication
def get_current_user():
    if 'user_id' in session:
        # FIX 2: Replace deprecated User.query.get() with db.session.get()
        return db.session.get(User, session['user_id'])
    return None

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email address is already registered.", "danger")
            return render_template('register.html')
            
        try:
            # Create user
            pw_hash = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=pw_hash)
            db.session.add(new_user)
            db.session.flush() # Populate user ID
            
            # Generate cryptographic keys
            private_key = crypto.generate_user_keypair()
            public_key_pem = crypto.get_public_key_pem(private_key)
            encrypted_private_key_pem = crypto.encrypt_private_key(private_key, password)
            fingerprint = crypto.get_public_key_fingerprint(public_key_pem)
            
            # Issue X.509 Certificate
            certificate_pem = crypto.issue_user_certificate(username, email, private_key.public_key())
            
            # Save certificate record
            new_cert = Certificate(
                user_id=new_user.id,
                public_key_pem=public_key_pem,
                encrypted_private_key_pem=encrypted_private_key_pem,
                certificate_pem=certificate_pem,
                fingerprint=fingerprint,
                is_active=True
            )
            db.session.add(new_cert)
            db.session.commit()
            
            # Authenticate user session
            session['user_id'] = new_user.id
            session['email'] = new_user.email
            session['username'] = new_user.username
            session['password'] = password # Keep password in session memory for signing messages
            
            flash("Account created and digital certificate issued successfully!", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed: {str(e)}", "danger")
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['username'] = user.username
            session['password'] = password # In-memory decryption key
            
            flash("Welcome back to SigNet!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out of your secure session.", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        flash("Please log in to access the mailbox.", "warning")
        return redirect(url_for('login'))
        
    # Get all received emails
    received_emails = Email.query.filter_by(recipient_email=user.email).order_by(Email.timestamp.desc()).all()
    # Get all sent emails
    sent_emails = Email.query.filter_by(sender_email=user.email).order_by(Email.timestamp.desc()).all()
    
    # Process received emails to dynamically check their status
    inbox_items = []
    for em in received_emails:
        verified, _ = verify_email_signature(em)
        inbox_items.append({
            'obj': em,
            'is_verified': verified,
            'sender_initials': em.sender_email[:2].upper()
        })
        
    return render_template('dashboard.html', user=user, inbox_items=inbox_items, sent_emails=sent_emails)

@app.route('/compose', methods=['POST'])
def compose():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
        
    recipient_email = request.form.get('recipient_email', '').strip().lower()
    subject = request.form.get('subject', '').strip()
    body = request.form.get('body', '')
    
    if not recipient_email or not subject or not body:
        flash("All fields are required to send an email.", "danger")
        return redirect(url_for('dashboard'))
        
    # Retrieve user private key
    cert_rec = Certificate.query.filter_by(user_id=user.id, is_active=True).first()
    if not cert_rec:
        flash("No active cryptographic credentials found. Please regenerate keys.", "danger")
        return redirect(url_for('dashboard'))
        
    try:
        # Decrypt private key with the user's password from session
        private_key = crypto.decrypt_private_key(cert_rec.encrypted_private_key_pem, session['password'])
        
        # Prepare signed message payload
        now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        payload = crypto.get_message_payload(
            user.email,
            recipient_email,
            subject,
            body,
            now_str
        )
        
        # Sign the payload
        signature = crypto.sign_message(private_key, payload)
        
        # Save to database
        new_email = Email(
            sender_email=user.email,
            recipient_email=recipient_email,
            subject=subject,
            body=body,
            signature=signature,
            timestamp=datetime.strptime(now_str, '%Y-%m-%d %H:%M:%S'),
            is_verified=True
        )
        
        db.session.add(new_email)
        db.session.commit()
        
        flash("Secure signed email sent successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error signing or sending email: {str(e)}", "danger")
        
    return redirect(url_for('dashboard'))

@app.route('/email/<int:email_id>')
def view_email(email_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
        
    # FIX 2 (continued): Use db.session.get() instead of query.get_or_404()
    email_obj = db.session.get(Email, email_id)
    if not email_obj:
        return jsonify({'error': 'Email not found'}), 404
    
    # Check authorization (must be sender or recipient)
    if email_obj.sender_email != user.email and email_obj.recipient_email != user.email:
        return jsonify({'error': 'Access denied'}), 403
        
    # Get sender information for cryptographic verification display
    sender_user = User.query.filter_by(email=email_obj.sender_email).first()
    fingerprint = "N/A"
    certificate_pem = "N/A"
    
    if sender_user:
        active_cert = Certificate.query.filter_by(user_id=sender_user.id, is_active=True).first()
        if active_cert:
            fingerprint = active_cert.fingerprint
            certificate_pem = active_cert.certificate_pem
            
    verified, verification_msg = verify_email_signature(email_obj)
    
    payload = crypto.get_message_payload(
        email_obj.sender_email,
        email_obj.recipient_email,
        email_obj.subject,
        email_obj.body,
        email_obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    )
    
    return jsonify({
        'id': email_obj.id,
        'sender': email_obj.sender_email,
        'recipient': email_obj.recipient_email,
        'subject': email_obj.subject,
        'body': email_obj.body,
        'signature': email_obj.signature,
        'timestamp': email_obj.timestamp.strftime('%Y-%m-%d %I:%M %p'),
        'verified': verified,
        'verification_message': verification_msg,
        'fingerprint': fingerprint,
        'certificate_pem': certificate_pem,
        'payload': payload
    })

@app.route('/profile')
def profile():
    user = get_current_user()
    if not user:
        flash("Please log in to view credentials.", "warning")
        return redirect(url_for('login'))
        
    cert_rec = Certificate.query.filter_by(user_id=user.id, is_active=True).first()
    
    # Load CA certificate for display
    ca_cert_pem = "CA Certificate Not Initialized"
    if os.path.exists(crypto.CA_CERT_PATH):
        with open(crypto.CA_CERT_PATH, 'r') as f:
            ca_cert_pem = f.read()
            
    return render_template('profile.html', user=user, certificate=cert_rec, ca_certificate_pem=ca_cert_pem)

@app.route('/profile/generate-keys', methods=['POST'])
def regenerate_keys():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
        
    password = request.form.get('password', '')
    if not password or not check_password_hash(user.password_hash, password):
        flash("Incorrect password verification.", "danger")
        return redirect(url_for('profile'))
        
    try:
        # Deactivate old certificates
        Certificate.query.filter_by(user_id=user.id).update({'is_active': False})
        
        # Generate new keys
        private_key = crypto.generate_user_keypair()
        public_key_pem = crypto.get_public_key_pem(private_key)
        encrypted_private_key_pem = crypto.encrypt_private_key(private_key, password)
        fingerprint = crypto.get_public_key_fingerprint(public_key_pem)
        
        # Issue X.509 Certificate
        certificate_pem = crypto.issue_user_certificate(user.username, user.email, private_key.public_key())
        
        # Save new Certificate record
        new_cert = Certificate(
            user_id=user.id,
            public_key_pem=public_key_pem,
            encrypted_private_key_pem=encrypted_private_key_pem,
            certificate_pem=certificate_pem,
            fingerprint=fingerprint,
            is_active=True
        )
        db.session.add(new_cert)
        db.session.commit()
        
        # Update session password key
        session['password'] = password
        
        flash("New key pair and digital certificate issued successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Key regeneration failed: {str(e)}", "danger")
        
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
