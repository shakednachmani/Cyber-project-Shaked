
from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)

# MySQL configuration (match these details with Workbench settings)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'flaskusers'
app.config['MYSQL_PASSWORD'] = '1993Sean!'
app.config['MYSQL_DB'] = 'users'

# Initialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    # Test the connection
    cur = mysql.connection.cursor()
    cur.execute("SELECT * from login_users")
    db = cur.fetchall()
    return f"{db}"
    
    
if __name__ == '__main__':
    app.run(debug=True)