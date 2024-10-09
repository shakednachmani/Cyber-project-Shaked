import os
import hmac
from datetime import datetime
import hashlib
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(50), unique=True, nullable=False)
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     password_hash = db.Column(db.String(64))  
#     salt = db.Column(db.LargeBinary(16))  
#     is_admin = db.Column(db.Boolean, default=False, nullable=False)
#     reset_token = db.Column(db.String(40), nullable=True)
#     token_expiry = db.Column(db.DateTime, nullable=True)
    
    
#     def set_password(self, password):
#         self.salt = os.urandom(16)  
#         self.password_hash = self.hash_password(password, self.salt)  # Hashing the original password once with the salt


#     def hash_password(self, password, salt):
#         return hmac.new(salt, password.encode('utf-8'), hashlib.sha256).hexdigest()



#     def check_password(self, password):
#         return hmac.new(self.salt, password.encode('utf-8'), hashlib.sha256).hexdigest() == self.password_hash


# class Clients(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(50), unique=True, nullable=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    