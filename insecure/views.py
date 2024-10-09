from flask import render_template, request, redirect, url_for, flash, session
from sqlalchemy import text
from models import db
from datetime import datetime

from sqlalchemy import text



def homepage():
    client = None  # Initialize a variable to store the most recent client

    # Query to fetch only the most recently added client
    query = text("SELECT username FROM clients ORDER BY id DESC LIMIT 1")
    
    try:
        # Execute the query to get the most recent client
        result = db.session.execute(query).fetchone()

        # If a client was found, process the result
        if result:
            client = {
                'username': result[0],  # Assuming 'username' is the only selected column
            }

    except Exception as e:
        flash(f"Error occurred while fetching the recent client: {e}")

    return render_template('index.html', client=client)



def client_details(username):
    
    query = text(f"SELECT username, user_code, address, created_at FROM clients WHERE username = '{username}'")
    print(query)

    try:
        result = db.session.execute(query).fetchall()
        print(result, 'this is the result')

        if result:
            clients = []
            for row in result:
                created_at = row[3]

                
                if isinstance(created_at, str):
                    try:
                        # Attempt to parse the string as a datetime
                        created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        pass  # If it cannot be parsed, leave it as is (likely due to injection)
                elif isinstance(created_at, int):
                    # If it's an integer, handle it as an integer and skip strftime
                    created_at = created_at  # No formatting for integer values

                client = {
                    'username': row[0],
                    'user_code': row[1],
                    'address': row[2],
                    'created_at': created_at,  # It will show as integer or unformatted if not datetime
                }
                clients.append(client)

            return render_template('client_details.html', clients=clients)
        else:
            flash('Client not found!')
            return redirect(url_for('homepage'))

    except Exception as e:
        flash(f"Error occurred while fetching the client details: {e}")
        return redirect(url_for('homepage'))


def add_client():
    username = request.form.get('username')
    user_code = request.form.get('user_code')
    address = request.form.get('address')

    # Check if username is provided
    if not username:
        flash('Username is required.')
        return redirect(url_for('homepage'))

    
    if not user_code:
        flash('User code is required.')
        return redirect(url_for('homepage'))

    
    query = text("INSERT INTO clients (username, user_code, address) VALUES (:username, :user_code, :address)")

    try:
       
        db.session.execute(query, {'username': username, 'user_code': user_code, 'address': address})
        db.session.commit()  # Commit the transaction

        
        flash(f'Client "{username}" added successfully with user code "{user_code}" and address "{address}"!')

    except Exception as e:
        db.session.rollback()
        flash(f"Error occurred while adding the client: {e}")

    
    return redirect(url_for('homepage'))