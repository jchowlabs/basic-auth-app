from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
import os

# Creates our flask app - "app"
app = Flask(__name__)

# Creates a SQLite database instance to store hashed id, username, password
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'jchowlabs' # TO CHANGE
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

# Creates user object from registration form
class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Name"})
    email = StringField(validators=[InputRequired(), Email(message="Please enter valid email address"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    # Checks if username already exists in database
    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("Email already exists.")

# Creates user object from login form
class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(message="Email is required"), Email(message="Please enter valid email address"), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(message="Password is required"), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

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
                flash('The email or password you entered is not valid.', 'danger')
        else:
            flash('The email or password you entered is not valid.', 'danger')
    return render_template('login.html', form=form)


# Route for registration page - no login required
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('User already exists', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route for dashboard - login required
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# Route that redirects logged out user to login page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ensure the database file exists and create tables if not
if not os.path.exists('database.db'):
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    app.run()
