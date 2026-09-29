from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    certificates = db.relationship('Certificate', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"

class Certificate(db.Model):
    __tablename__ = 'certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    encrypted_private_key_pem = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Certificate Fingerprint={self.fingerprint} Active={self.is_active}>"

class Email(db.Model):
    __tablename__ = 'emails'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_email = db.Column(db.String(120), nullable=False, index=True)
    recipient_email = db.Column(db.String(120), nullable=False, index=True)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Email from={self.sender_email} to={self.recipient_email} Verified={self.is_verified}>"
