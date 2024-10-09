from flask import render_template, request, redirect, flash, session, url_for
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from models import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
import hashlib
import os
from extensions import mail
import hmac
import re
import yaml

def load_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

config = load_config('config.yaml')

def is_password_legal(password, config):
    if len(password) < config['password_policy']['min_length']:
        return False, f"Password must be at least {config['password_policy']['min_length']} characters long."
    
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

def signup():
    return render_template('signup.html')

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

        # Password validation using the policy in the config file
        password_is_valid, message = is_password_legal(password, config)
        if not password_is_valid:
            flash(message)
            return render_template('signup.html', username=username, email=email)

        hashed_password, salt = hash_password(password)
        salt_hex = salt.hex()

        # Check if the user or email already exists
        query = text("SELECT * FROM User WHERE username = :username OR email = :email")
        existing_user = db.session.execute(query, {'username': username, 'email': email}).fetchone()

        if existing_user:
            flash('This username or email is already taken. Please choose a different one.')
            return render_template('signup.html', username=username, email=email)

        # Insert new user into the database
        insert_query = text("INSERT INTO User (username, email, password_hash, salt) VALUES (:username, :email, :password_hash, :salt)")
        
        try:
            db.session.execute(insert_query, {
                'username': username,
                'email': email,
                'password_hash': hashed_password,
                'salt': salt_hex
            })
            db.session.commit()
            flash('User registered successfully!')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('This username or email is already taken. Please choose a different one.')
            return render_template('signup.html', username=username, email=email)
        except Exception as e:
            db.session.rollback()
            flash(f"An unexpected error occurred: {e}")
            return render_template('signup.html', username=username, email=email)

    return render_template('signup.html')

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure: Directly concatenating user input into the SQL query (vulnerable to SQL Injection)
        query = f"SELECT password_hash, salt FROM User WHERE username = '{username}'"

        try:
            
            result = db.session.execute(text(query)).fetchone()

            if result:
                session.clear()
                session['username'] = username
                session['is_logged_in'] = True
                flash("Successfully logged in (without password check)!")
                return redirect(url_for('homepage'))
            else:
                flash('Invalid username or password')
                return render_template('login.html', username=username)

        except Exception as e:
            flash(f"An error occurred: {e}")
            return render_template('login.html', username=username)

    return render_template('login.html')

# Logout function
def logout():
    session.pop('username', None)
    session['is_logged_in'] = False
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Change password function
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        username = session.get('username')

        if not username:
            flash('User not logged in.')
            return redirect(url_for('login'))

        # Fetch user's current password hash and salt
        query = text("SELECT password_hash, salt FROM User WHERE username = :username")
        user_data = db.session.execute(query, {'username': username}).fetchone()

        if not user_data:
            flash('User not found.')
            return redirect(url_for('login'))

        stored_password_hash, stored_salt = user_data

        # Check if the current password is correct
        if not check_password_hash(stored_password_hash, current_password):
            flash('Current password is incorrect.')
            return render_template('change_password.html')

        # Check if the new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.')
            return render_template('change_password.html')

        # Password validation using the policy in the config file
        password_is_valid, message = is_password_legal(new_password, config)
        if not password_is_valid:
            flash(message)
            return render_template('change_password.html')

        # Hash the new password and update it in the database
        hashed_password = generate_password_hash(new_password)
        update_query = text("""
            UPDATE User
            SET password_hash = :hashed_password
            WHERE username = :username
        """)

        try:
            db.session.execute(update_query, {
                'hashed_password': hashed_password,
                'username': username
            })
            db.session.commit()
            flash('Password changed successfully.')
            return redirect(url_for('homepage'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while changing the password. Please try again.')
            return render_template('change_password.html')

    return render_template('change_password.html')



def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        query = text("SELECT * FROM User WHERE email = :email")
        result = db.session.execute(query, {'email': email}).fetchone()

        if result:
            token = generate_reset_token()
            token_expiry = datetime.utcnow() + timedelta(hours=1)
            update_query = text("""
                UPDATE User
                SET reset_token = :token, token_expiry = :expiry
                WHERE email = :email
            """)
            db.session.execute(update_query, {'token': token, 'expiry': token_expiry, 'email': email})
            db.session.commit()

            send_reset_email(email, token)

        flash('If an account with that email exists, a password reset token has been sent.')
        return render_template('enter_token.html', email=email)

    return render_template('forgot_password.html')

# Generate reset token function
def generate_reset_token():
    random_bytes = os.urandom(16)
    token = hashlib.sha1(random_bytes).hexdigest()  # Generate SHA-1 token
    return token

# Send reset email function
def send_reset_email(email, token):
    msg = Message(subject="Password Reset Request",
                  sender="noreply@communicationltd.com",
                  recipients=[email])
    
    msg.body = f"Your password reset token is: {token}\n\n" \
               f"If you did not request this, please ignore this email."
    
    mail.send(msg)

# Enter token function
def enter_token():
    if request.method == 'POST':
        email = request.form['email']
        input_token = request.form['token']

        query = text("SELECT reset_token, token_expiry FROM User WHERE email = :email")
        result = db.session.execute(query, {'email': email}).fetchone()

        if not result:
            flash('Invalid email or token.')
            return render_template('enter_token.html', email=email)

        stored_token, token_expiry_str = result

        try:
            token_expiry = datetime.strptime(token_expiry_str, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            flash('Invalid token expiry format.')
            return render_template('enter_token.html', email=email)

        if stored_token != input_token or datetime.utcnow() > token_expiry:
            flash('Invalid or expired token.')
            return render_template('enter_token.html', email=email)

        session['reset_email'] = email
        return redirect(url_for('reset_password'))

    return render_template('enter_token.html')

# Reset password function
def reset_password():
    if 'reset_email' not in session:
        flash('Unauthorized access.')
        return redirect(url_for('login'))

    email = session['reset_email']

    query = text("SELECT * FROM User WHERE email = :email")
    result = db.session.execute(query, {'email': email}).fetchone()

    if not result:
        flash('User not found.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.')
            return render_template('reset_password.html')

        # Password validation using the policy in the config file
        password_is_valid, message = is_password_legal(new_password, config)
        if not password_is_valid:
            flash(message)
            return render_template('reset_password.html')

        # Update the user's password
        hashed_password = generate_password_hash(new_password)
        update_query = text("""
            UPDATE User
            SET password_hash = :password_hash, reset_token = NULL, token_expiry = NULL
            WHERE email = :email
        """)
        try:
            db.session.execute(update_query, {'password_hash': hashed_password, 'email': email})
            db.session.commit()
            session.pop('reset_email', None)
            flash('Your password has been successfully updated.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the password. Please try again.')
            return render_template('reset_password.html')

    return render_template('reset_password.html')
