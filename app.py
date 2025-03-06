import os
import json
import base64
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, url_for, redirect, flash, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Regexp
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Initializes a Flask app with secret keys and database URI
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PASSWORD_PEPPER'] = os.environ.get('PASSWORD_PEPPER', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = False

############################### CONFIGURATION FOR LOCALHOST ######################################
#app.config['WEBAUTHN_RP_ID'] = 'localhost'  
#app.config['WEBAUTHN_RP_NAME'] = 'Login Demo'
#app.config['WEBAUTHN_ORIGIN'] = 'https://localhost:5000'
##################################################################################################

################################ CONFIGURATION WITH NGROK ########################################
app.config['WEBAUTHN_RP_ID'] = '1a46-2601-640-8d00-eda0-487-bd05-7e58-2578.ngrok-free.app'          # Replace with your own ngrok domain
app.config['WEBAUTHN_RP_NAME'] = 'Login Demo'    
app.config['WEBAUTHN_ORIGIN'] = 'https://1a46-2601-640-8d00-eda0-487-bd05-7e58-2578.ngrok-free.app' # Replace with your own ngrok domain
##################################################################################################

# Initializes database, bcrypt, and Flask login manager
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Loads user objects from database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Model with index on email
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

# WebAuthn Credential Model with index on credential_id
class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.String(250), nullable=False, index=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('credentials', lazy=True))

# Password validator for registration form
def password_strength_check(form, field):

    password = field.data
    errors = []

    if len(password) < 8:
        errors.append("Must be at least 8 characters.")
    if not any(char.isdigit() for char in password):
        errors.append("Must contain at least one number.")
    if not any(char.isupper() for char in password):
        errors.append("Must contain at least one uppercase letter.")
    if not any(char.islower() for char in password):
        errors.append("Must contain at least one lowercase letter.")
    if not any(char in '!@#$%^&*(),.?":{}|<>' for char in password):
        errors.append("Must contain at least one special character.")
    if errors:
        raise ValidationError("Password does not meet requirements.")

# Creates user object from registration form
class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Name"})
    email = StringField(validators=[InputRequired(), Email(message="Please enter a valid email."), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=72), password_strength_check], render_kw={"placeholder": "Password", "autocomplete": "new-password"})
    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("Email already exists.")

# Creates user object from login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(message="Email is required."), Email(message="Please enter a valid email."), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(message="Password is required."), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Generates a random challenge for WebAuthn
def generate_challenge():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# Configurations for rate limiting login attempts
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "25 per hour"],
    storage_uri="memory://",
    strategy="fixed-window" 
)

# Rate limiting handler for too many requests
@app.errorhandler(429) 
def ratelimit_handler(e):
    flash('Too fast - try again in 1 minute.', 'danger')
    return render_template('login.html', form=LoginForm()) 

# Default home route for logging in user
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute") 
def login():

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                remaining_time = (user.locked_until - datetime.utcnow()).total_seconds() / 60
                flash(f'Too many invalid attempts - try again in {int(remaining_time)} minutes.', 'danger')
                return render_template('login.html', form=form)
            
            peppered_password = form.password.data + app.config['PASSWORD_PEPPER']
            if bcrypt.check_password_hash(user.password, peppered_password):
                user.failed_login_attempts = 0
                db.session.commit()
                limiter.storage.clear(get_remote_address())
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    flash('Too many invalid attempts - try again in 5 minutes.', 'danger')
                else:
                    flash('Invalid email or password', 'danger')
                db.session.commit()
        else:
            flash('Invalid email or password.', 'danger')
        
    return render_template('login.html', form=form)


# Route for registering new user
@app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm()
    
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Account already exists.', 'danger')
        else:
            peppered_password = form.password.data + app.config['PASSWORD_PEPPER']
            hashed_password = bcrypt.generate_password_hash(peppered_password).decode('utf-8')
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account successfully created!', 'success')
            return redirect(url_for('login'))
    
    if form.errors and 'password' in form.errors:
        flash('Please ensure your password meets all requirements.', 'warning')
    return render_template('register.html', form=form)

# Route for user dashboard - protected by login
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

# WebAuthN API route for registration
@app.route('/api/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    
    # Generates a challenge for registration
    challenge = generate_challenge()
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
        'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}, {'type': 'public-key', 'alg': -257}],
        'timeout': 60000, 
        'attestation': 'none',
        'authenticatorSelection': {'userVerification': 'preferred', 'requireResidentKey': False}
    }
    return jsonify(options)

# WebAuthN API route for completing registration
@app.route('/api/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():

    # Registers new credential for user
    try:
        data = request.json
        challenge = session.get('challenge')
        if not challenge:
            return jsonify({'error': 'Challenge not found.'}), 400
        session.pop('challenge', None)
        
        # Gets credential ID and public key
        credential_id = data['id']
        public_key = json.dumps(data['response'])
        
        # Checks if credential already exists
        existing_cred = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if existing_cred:
            return jsonify({'error': 'Credential already registered.'}), 400
        
        # Creates new credential object
        new_credential = WebAuthnCredential(
            user_id=current_user.id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=0
        )
        
        # Save credential to database
        db.session.add(new_credential)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Successfully registered Passkey.'})

    # Returns error message if registration fails    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebAuthN API route for authenticating user
@app.route('/api/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():

    # Authenticates user with credential
    try:
        # Generate challenge for authentication
        challenge = generate_challenge()
        session['auth_challenge'] = challenge
        
        # Gets all credentials available for authentication
        credentials = WebAuthnCredential.query.all()
        allowed_credentials = []
        
        for cred in credentials:
            allowed_credentials.append({
                'type': 'public-key',
                'id': cred.credential_id
            })
        
        # Creates authentication options
        options = {
            'challenge': challenge,
            'timeout': 60000,
            'rpId': app.config['WEBAUTHN_RP_ID'],
            'allowCredentials': allowed_credentials,
            'userVerification': 'preferred'
        }
        return jsonify(options)

    # Returns error message if authentication fails    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebAuthN API route for completing authentication
@app.route('/api/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():

    # Authenticates user with credential
    try:
        data = request.json
        credential_id = data['id']
        
        # Gets challenge from session
        challenge = session.get('auth_challenge')
        if not challenge:
            return jsonify({'error': 'Challenge not found.'}), 400
        session.pop('auth_challenge', None)
        
        # Finds credential in database
        credential = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            return jsonify({'error': 'Unknown credential'}), 400
        
        # Get user associated with credential
        user = User.query.get(credential.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 400
        
        # Updates the signature count if available
        if 'authenticatorData' in data['response'] and hasattr(data['response'], 'signCount'):
            credential.sign_count = data['response']['signCount']
            db.session.commit()
        
        # Logs in the user
        login_user(user)
        
        return jsonify({
            'success': True,
            'message': 'Authentication successful.',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Creates database if it does not exist
if not os.path.exists('database.db'):
    with app.app_context():
        db.create_all()
else:
    with app.app_context():
        db.create_all()

########### CONFIGURATION FOR LOCALHOST ##############
#def main():
    #app.run(ssl_context="adhoc")
######################################################

############ CONFIGURATION WITH NGROK ################
def main():
    app.run()
######################################################

if __name__ == '__main__':
    main()