from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta, timezone
from pytz import timezone as tz
from app import db

phnom_penh_tz = tz('Asia/Phnom_Penh')

class TokenRequestLog(db.Model):
    __tablename__ = 'token_request_log'

    id = db.Column(db.Integer, primary_key=True)
    token_type = db.Column(db.String(50), nullable=False)
    access_token = db.Column(db.String(512), nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    def __init__(self, token_type, access_token, **kwargs):
        super().__init__(**kwargs)
        self.token_type = token_type
        self.access_token = access_token
        self.set_expires()

    def set_expires(self):
        self.expires = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=7)
        self.expires = self.expires.astimezone(phnom_penh_tz)

    def update_timestamp(self):
        self.updated_at = datetime.utcnow() + timedelta(hours=7)

    def __repr__(self):
        return f"<TokenRequestLog(access_token='{self.access_token}', token_type='{self.token_type}', created_at='{self.created_at}', updated_at='{self.updated_at}', expires='{self.expires}', active='{self.active}')>"


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User(email='{self.email}')>"


class UserLogin(db.Model):
    __tablename__ = 'userLogin'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    access_token = db.Column(db.String(512))  # Adjust length as necessary
    expires_in = db.Column(db.Integer)  # Adjust data type as necessary
    status_code = db.Column(db.Integer)  # Adjust data type as necessary
    active = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<UserLogin(username='{self.username}', email='{self.email}', timestamp='{self.timestamp}')>"