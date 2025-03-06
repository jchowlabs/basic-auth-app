from flask import Flask, render_template, url_for, redirect, flash, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
import os
import json
import base64
import secrets
from datetime import datetime

# Creates our flask app - "app"
app = Flask(__name__)

# Creates a SQLite database instance to store hashed id, username, password
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'jchowlabs' 
app.config['WEBAUTHN_RP_ID'] = 'localhost'  
app.config['WEBAUTHN_RP_NAME'] = 'Login Demo'
app.config['WEBAUTHN_ORIGIN'] = 'https://localhost:5000'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Enables handling between flask app and login system
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Reloads user object from user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Creates database table with id, username, password columns
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

# WebAuthn Credentials Model
class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.String(250), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with the User
    user = db.relationship('User', backref=db.backref('credentials', lazy=True))

# Creates user object from registration form
class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Name"})
    email = StringField(validators=[InputRequired(), Email(message="Invalid email address."), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    # Checks if username already exists in database
    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("Email already exists.")

# Creates user object from login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(message="Email is required."), Email(message="Invalid email address."), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(message="Password is required."), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Generate a random challenge
def generate_challenge():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# Route for login page - no login required
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'danger')
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


# Route for registration page - no login required
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Account already exists.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account successfully created! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route for dashboard - login required
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    has_credentials = WebAuthnCredential.query.filter_by(user_id=current_user.id).first() is not None
    return render_template('dashboard.html', has_credentials=has_credentials)

# Route that redirects logged out user to login page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# WebAuthn registration routes
@app.route('/api/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    # Generate registration options
    challenge = generate_challenge()
    
    # Store the challenge in the session for verification later
    session['challenge'] = challenge
    
    # Create registration options
    options = {
        'challenge': challenge,
        'rp': {
            'name': app.config['WEBAUTHN_RP_NAME'],
            'id': app.config['WEBAUTHN_RP_ID']
        },
        'user': {
            'id': str(current_user.id),
            'name': current_user.email,
            'displayName': current_user.name
        },
        'pubKeyCredParams': [
            {'type': 'public-key', 'alg': -7},  # ES256
            {'type': 'public-key', 'alg': -257}  # RS256
        ],
        'timeout': 60000,  # 60 seconds
        'attestation': 'none',
        'authenticatorSelection': {
            'userVerification': 'preferred',
            'requireResidentKey': False
        }
    }
    
    return jsonify(options)

@app.route('/api/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    try:
        data = request.json
        
        # Get stored challenge from session
        challenge = session.get('challenge')
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 400
            
        # Clear the challenge from the session
        session.pop('challenge', None)
        
        # Verify attestation response from client
        # In a production system, you would properly verify the attestation
        # Here we'll just save the credential
        
        credential_id = data['id']
        public_key = json.dumps(data['response'])
        
        # Check if credential already exists
        existing_cred = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if existing_cred:
            return jsonify({'error': 'Credential already registered'}), 400
        
        # Create new credential
        new_credential = WebAuthnCredential(
            user_id=current_user.id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=0
        )
        
        db.session.add(new_credential)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Passkey registered successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebAuthn authentication routes
@app.route('/api/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():
    try:
        # Generate authentication challenge
        challenge = generate_challenge()
        
        # Store challenge in session for verification
        session['auth_challenge'] = challenge
        
        # Get all credentials to allow for authentication
        # In a real app, you might want to filter by username first
        credentials = WebAuthnCredential.query.all()
        allowed_credentials = []
        
        for cred in credentials:
            allowed_credentials.append({
                'type': 'public-key',
                'id': cred.credential_id
            })
        
        # Create authentication options
        options = {
            'challenge': challenge,
            'timeout': 60000,
            'rpId': app.config['WEBAUTHN_RP_ID'],
            'allowCredentials': allowed_credentials,
            'userVerification': 'preferred'
        }
        
        return jsonify(options)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():
    try:
        data = request.json
        
        # Get credential ID from authentication response
        credential_id = data['id']
        
        # Get challenge from session
        challenge = session.get('auth_challenge')
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 400
        
        # Clear challenge from session
        session.pop('auth_challenge', None)
        
        # Find credential in database
        credential = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            return jsonify({'error': 'Unknown credential'}), 400
        
        # Get user associated with credential
        user = User.query.get(credential.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 400
        
        # In a real application, you would verify the authenticator assertion here
        # For this demo, we'll skip the cryptographic validation and trust the credential
        
        # Update the sign count if available
        if 'authenticatorData' in data['response'] and hasattr(data['response'], 'signCount'):
            credential.sign_count = data['response']['signCount']
            db.session.commit()
        
        # Log in the user
        login_user(user)
        
        return jsonify({
            'success': True,
            'message': 'Authentication successful',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Ensure the database file exists and create tables if not
if not os.path.exists('database.db'):
    with app.app_context():
        db.create_all()
else:
    # Update schema for existing database
    with app.app_context():
        db.create_all()

def main():
    app.run(ssl_context="adhoc")

if __name__ == '__main__':
    main()