from flask import render_template, request, redirect, url_for, flash
from models import Clients
from models import db
import re
from sqlalchemy.exc import IntegrityError
from datetime import datetime

# Function to validate the username
def is_valid_username(username):
    # Only allow letters, numbers, and underscores
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

# Function to validate the user_code
def is_valid_user_code(user_code):
    # Only allow numbers
    return bool(re.match(r'^[0-9]+$', user_code))

# Function to validate the address
def is_valid_address(address):
    # Allow letters, numbers, spaces, and some punctuation but no HTML tags
    return bool(re.match(r'^[a-zA-Z0-9\s,.-]+$', address))

# Add client  XSS protection
def add_client():
    username = request.form['username']
    user_code = request.form['user_code']
    address = request.form['address']
    
    # Validate input fields
    if not username or not is_valid_username(username):
        flash("Invalid username. Only letters, numbers, and underscores are allowed.")
        return redirect(url_for('homepage'))

    if not user_code or not is_valid_user_code(user_code):
        flash("Invalid user code. Only numbers are allowed.")
        return redirect(url_for('homepage'))

    if not address or not is_valid_address(address):
        flash("Invalid address. No HTML or scripts are allowed.")
        return redirect(url_for('homepage'))
    
    # Proceed with adding the client if all inputs are valid
    new_client = Clients(username=username, user_code=user_code, address=address)
    db.session.add(new_client)
    
    try:
        db.session.commit()
        flash('Client added successfully!')
    except IntegrityError:
        db.session.rollback()
        flash('This username or user code already exists. Please choose a different one.')

    return redirect(url_for('homepage'))

# Homepage function to show the most recently added client
def homepage():
    # Query to get the most recently added client
    recent_client = Clients.query.order_by(Clients.id.desc()).first()
    return render_template('index.html', client=recent_client)

# Client details function to show the details of a specific client
def client_details(username):
    # Fetch the client by username safely using SQLAlchemy's query filter
    client = Clients.query.filter_by(username=username).first()

    if not client:
        flash('Client not found!')
        return redirect(url_for('homepage'))

    # If the client exists, render the details page
    return render_template('client_details.html', client=client)
