import os
import hmac 
from datetime import datetime
import hashlib
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    """
    Represents a user in the system with authentication details, 
    including password hashing and salting for security.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)  # Hash for the password
    salt = db.Column(db.LargeBinary(16), nullable=False)  # Store the salt as raw bytes for hashing
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    reset_token = db.Column(db.String(40), nullable=True)  # Token for password reset
    token_expiry = db.Column(db.DateTime, nullable=True)  # Expiry time for the reset token

    def set_password(self, password):
        """
        Generates a salt and hashes the password using HMAC and SHA-256.
        """
        self.salt = os.urandom(16)  
        self.password_hash = self.hash_password(password, self.salt)  # Hash the password with the generated salt

    def hash_password(self, password, salt):
        """
        Hashes the password with the provided salt using HMAC and SHA-256.
        """
        return hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()

    def check_password(self, password):
        """
        Verifies the password by hashing the provided password with the stored salt
        and comparing it to the stored password hash.
        """
        return hmac.new(self.salt, password.encode('utf-8'), hashlib.sha256).hexdigest() == self.password_hash


class Clients(db.Model):
    """
    Represents a client in the system with identifying details such as username, 
    user_code, and address.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)  # Unique username for each client
    user_code = db.Column(db.String(20), nullable=False)  # Client's code, which is a required field
    address = db.Column(db.String(120), nullable=True)  # Optional address field for the client
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Timestamp of creation

    def __repr__(self):
        return f'<Client {self.username}>'
