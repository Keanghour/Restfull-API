from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from app import db


class auth_TokenRequestLog(db.Model):
    __tablename__ = 'auth_token_request_log'

    id = db.Column(db.Integer, primary_key=True)
    token_type = db.Column(db.String(50), nullable=False)
    access_token = db.Column(db.String(512), nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    def __init__(self, token_type, access_token):
        self.token_type = token_type
        self.access_token = access_token
        self.set_expires()

    def set_expires(self):
        self.expires = datetime.utcnow() + timedelta(hours=7)

    def __repr__(self):
        return f"<auth_TokenRequestLog(access_token='{self.access_token}', token_type='{self.token_type}', created_at='{self.created_at}', updated_at='{self.updated_at}', expires='{self.expires}', active='{self.active}')>"

class auth_User(db.Model):
    __tablename__ = 'auth_users'

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
        return f"<auth_User(email='{self.email}')>"

class auth_UserLogin(db.Model):
    __tablename__ = 'auth_user_login'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    access_token = db.Column(db.String(512), nullable=False)
    expires_in = db.Column(db.Integer, nullable=False)
    token_type = db.Column(db.String(50), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<auth_UserLogin(username='{self.username}', email='{self.email}', created_at='{self.created_at}')>"

class auth_OTP(db.Model):
    __tablename__ = 'auth_otp_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    payload_resend = db.Column(db.JSON, nullable=True)
    payload_verify = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<OTP(user_id={self.user_id}, email{self.email}, otp_code={self.otp_code}, verified={self.verified})>"

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def verify(self, otp_code):
        if self.is_expired():
            return False, "OTP code has expired"
        if self.otp_code != otp_code:
            return False, "Invalid OTP code"
        self.verified = True
        self.payload_verify = {
            "message": "success",
            "status": 200,
            "data": {
                "message": "OTP code verified successfully"
            }
        }
        db.session.commit()
        return True, "OTP code verified successfully"

