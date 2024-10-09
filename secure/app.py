from flask import Flask
from urls import configure_routes
from flask_migrate import Migrate
from models import db
import os
from flask_mail import Mail, Message
from extensions import mail
app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ShakedNahmine')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///site.db"

db.init_app(app)
migrate = Migrate(app, db)
configure_routes(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dlevy651@gmail.com'
app.config['MAIL_PASSWORD'] = 'ngqf uozq wxgf utpf'


mail.init_app(app)




if __name__ == "__main__":
    app.run('0.0.0.0', port=5001, debug=True)
    