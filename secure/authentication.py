from flask import render_template, request, redirect, flash, session, url_for
from werkzeug.security import check_password_hash
from models import db
from sqlalchemy.exc import IntegrityError
import os
import hmac
import hashlib
import re
import yaml
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from extensions import mail
from models import db, User
from models import Clients




# Load config from YAML file for password policies
def load_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

config = load_config('config.yaml')

def signup():
    return render_template('signup.html')

def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        username = session.get('username')
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('User not found.')
            return redirect(url_for('login'))

        if not user.check_password(current_password):
            flash('Current password is incorrect.')
            return render_template('ChangePassword.html')

        if new_password != confirm_password:
            flash('New passwords do not match.')
            return render_template('ChangePassword.html')

        password_is_valid, message = is_password_legal(new_password, config)
        if not password_is_valid:
            flash(message)
            return render_template('ChangePassword.html')

        hashed_password, salt = hash_password(new_password)
        user.password_hash = hashed_password
        user.salt = salt

        try:
            db.session.commit()
            flash('Password changed successfully.')
            return redirect(url_for('homepage'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while changing the password. Please try again.')
            return render_template('ChangePassword.html')

    return render_template('ChangePassword.html')


def is_password_legal(password, config):
    if len(password) < config['password_policy']['min_length']:
        return False, "Password must be at least {} characters long.".format(config['password_policy']['min_length'])
    
    if config['password_policy']['complexity']['uppercase'] and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if config['password_policy']['complexity']['lowercase'] and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if config['password_policy']['complexity']['digits'] and not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    if config['password_policy']['complexity']['special_characters'] and not re.search(r'[!@#&%]', password):
        return False, "Password must contain at least one special character."

    return True, ""

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()
    return hashed, salt

def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!")
            return render_template('signup.html', username=username, email=email)

        # Validate the password based on policy
        password_is_valid, message = is_password_legal(password, config)
        if not password_is_valid:
            flash(message)
            return render_template('signup.html', username=username, email=email)

        # Hash the password and generate a salt
        hashed_password, salt = hash_password(password)

        # Create a new user object (Ensure salt is stored as string, not bytes)
        new_user = User(username=username, email=email, password_hash=hashed_password, salt=salt)

        try:
            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('This username or email is already taken. Please choose a different one.')
            return render_template('signup.html', username=username, email=email)

    return render_template('signup.html')

def signin_page():
    return render_template("login.html")

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session['username'] = user.username
            session['is_logged_in'] = True
            session['is_admin'] = user.is_admin
            return redirect(url_for('homepage'))
        else:
            flash('Invalid username or password')
            return render_template('login.html', username=username)

    return render_template('login.html')

def logout():
    session.pop('username', None)
    session['is_logged_in'] = False
    return redirect(url_for('login'))

def generate_reset_token():
    random_bytes = os.urandom(16)
    token = hashlib.sha1(random_bytes).hexdigest()  # Generate SHA-1 token
    return token

def send_reset_email(user, token):
    msg = Message(subject="Password Reset Request",
                  sender="noreply@communicationltd.com",
                  recipients=[user.email])
    
    msg.body = f"Your password reset token is: {token}\n\n" \
               f"If you did not request this, please ignore this email."
    
    mail.send(msg)

def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token()
            user.reset_token = token
            user.token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            send_reset_email(user, token)

        flash('If an account with that email exists, a password reset token has been sent.')
        return render_template('enter_token.html', email=email)

    return render_template('forgot_password.html')

def enter_token():
    if request.method == 'POST':
        email = request.form['email']
        input_token = request.form['token']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Invalid email or token.')
            return render_template('enter_token.html', email=email)

        if user.reset_token != input_token or user.token_expiry < datetime.utcnow():
            flash('Invalid or expired token.')
            return render_template('enter_token.html', email=email)

        session['reset_email'] = email
        return redirect(url_for('reset_password'))
    else:
        email = request.args.get('email', '')
        return render_template('enter_token.html', email=email)

def reset_password():
    if 'reset_email' not in session:
        flash('Unauthorized access.')
        return redirect(url_for('login'))

    email = session['reset_email']
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New passwords do not match.')
            return render_template('reset_password.html')

        password_is_valid, message = is_password_legal(new_password, config)
        if not password_is_valid:
            flash(message)
            return render_template('reset_password.html')

        user.set_password(new_password)
        user.reset_token = None
        user.token_expiry = None

        try:
            db.session.commit()
            session.pop('reset_email', None)
            flash('Your password has been successfully updated.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while updating the password. Please try again.')
            return render_template('reset_password.html')

    return render_template('reset_password.html')

# Input validation functions for XSS protection
def is_valid_username(username):
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def is_valid_user_code(user_code):
    return bool(re.match(r'^[0-9]+$', user_code))

def is_valid_address(address):
    return bool(re.match(r'^[a-zA-Z0-9\s,.-]+$', address))

# Function to add client with XSS protection
def add_client():
    username = request.form['username']
    user_code = request.form['user_code']
    address = request.form['address']
    
    if not username or not is_valid_username(username):
        flash("Invalid username. Only letters, numbers, and underscores are allowed.")
        return redirect(url_for('homepage'))

    if not user_code or not is_valid_user_code(user_code):
        flash("Invalid user code. Only numbers are allowed.")
        return redirect(url_for('homepage'))

    if not address or not is_valid_address(address):
        flash("Invalid address. No HTML or scripts are allowed.")
        return redirect(url_for('homepage'))

    new_client = Clients(username=username, user_code=user_code, address=address)
    db.session.add(new_client)

    try:
        db.session.commit()
        flash('Client added successfully!')
    except IntegrityError:
        db.session.rollback()
        flash('This username or user code already exists. Please choose a different one.')

    return redirect(url_for('homepage'))

# Display the most recently added client
def homepage():
    recent_client = Clients.query.order_by(Clients.id.desc()).first()
    return render_template('index.html', client=recent_client)
