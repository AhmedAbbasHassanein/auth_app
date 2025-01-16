from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)  # For admin approval
    is_active = db.Column(db.Boolean, default=True)    # For user activation status
    code = db.Column(db.String(20), nullable=False)    # New field for user code

    def __repr__(self):
        return f'<User {self.username}>'