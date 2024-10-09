from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'flaskusers'
app.config['MYSQL_PASSWORD'] = '1993Sean!'
app.config['MYSQL_DB'] = 'users'

# Initialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM clients")  # Adjust based on your table structure
    db = cur.fetchall()
    return f"{db}"

# Route to update clients table
@app.route('/update_clients_table')
def update_clients_table():
    try:
        cur = mysql.connection.cursor()
        # Add the columns user_code and address
        cur.execute("ALTER TABLE clients ADD COLUMN user_code VARCHAR(20) NOT NULL;")
        cur.execute("ALTER TABLE clients ADD COLUMN address VARCHAR(120);")
        mysql.connection.commit()  # Commit the changes
        return "Columns user_code and address added to clients table."
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == '__main__':
    app.run(debug=True)
