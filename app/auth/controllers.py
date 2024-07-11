import random
import string
from flask import current_app, jsonify
from flask_jwt_extended import create_access_token
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from pytz import timezone  # Import pytz for timezone handling
from .models import User, UserLogin, TokenRequestLog
from app import db

phnom_penh_tz = timezone('Asia/Phnom_Penh')  # Define Phnom Penh timezone

def generate_otp():
    return ''.join(random.choices(string.digits, k=4))

def generate_reset_token(user):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(user.email, salt='password-reset-salt')
    return token

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None
    return User.query.filter_by(email=email).first()

def request_password_reset(data):
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        otp_code = generate_otp()
        token = generate_reset_token(user)
        expires_at = datetime.now(tz=phnom_penh_tz) + timedelta(hours=7)

        response_data = {
            "message": "success",
            "status": 200,
            "data": {
                "forgot_password": {
                    "message": "OTP code sent successfully, Please check your email",
                    "expires_at": expires_at.isoformat() + 'Z',
                    "password_token": token,
                    "otp_code": otp_code
                }
            }
        }
        # TODO: Send email with the OTP code and reset link
    else:
        response_data = {
            "message": "success",
            "status": 200,
            "data": {
                "forgot_password": {
                    "message": "If your email address exists in our database, you will receive a password reset email shortly.",
                }
            }
        }
    return jsonify(response_data), 200

def generate_token(client_secret, grant_type, client_id):
    additional_claims = {
        'type': 'jwt',
        'client_id': client_id,
        'grant_type': grant_type,
        'client_secret': client_secret,
    }
    access_token = create_access_token(identity=client_id, additional_claims=additional_claims, expires_delta=timedelta(hours=7))

    # Determine the token type (jwt or bearer)
    token_type = "bearer" if grant_type == "bearer" else "jwt"

    # Log token request
    token_log = TokenRequestLog.query.filter_by(access_token=access_token).first()
    if token_log:
        token_log.increment_request_count()
    else:
        token_log = TokenRequestLog(token_type=token_type, access_token=access_token)
        db.session.add(token_log)
    db.session.commit()

    response = {
        "data": {
            "jwt": {
                "access_token": access_token,
                "expires_in": 3600,
                "token_type": token_type
            }
        },
        "message": "success",
        "status": 200
    }
    return response

def register_user(data):
    full_name = data.get('full_name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    password_confirmation = data.get('password_confirmation')

    if password != password_confirmation:
        return jsonify({"message": "error", "status": 422, "data": {"password": ["Passwords do not match."]}}), 422

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"message": "error", "status": 422, "data": {"email": ["The email has already been taken."]}}), 422

    new_user = User(full_name=full_name, email=email, username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    response = {
        "message": "success",
        "status": 200,
        "data": {
            "message": "User created successfully, Please verify your email address"
        }
    }
    return jsonify(response), 200

def user_login(data):
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid username or password", "status": 401}), 401

    # Generate JWT token with additional claims
    access_token = create_access_token(identity=user.username,
                                       additional_claims={
                                           'full_name': user.full_name,
                                           'username': user.username
                                       },
                                       expires_delta=timedelta(hours=7))

    # Save the login details
    login_entry = UserLogin(username=user.username, email=user.email, access_token=access_token, expires_in=3600, status_code=200)
    db.session.add(login_entry)
    db.session.commit()

    response = {
        "message": "success",
        "status": 200,
        "data": {
            "jwt": {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 3600
            }
        }
    }
    return jsonify(response), 200

def reset_password(data):
    password = data.get('password')
    password_confirmation = data.get('password_confirmation')
    token = data.get('password_token')

    if password != password_confirmation:
        return jsonify({"message": "error", "status": 422, "data": {"password": ["Passwords do not match."]}}), 422

    user = verify_reset_token(token)
    if not user:
        return jsonify({"message": "error", "status": 400, "data": {"token": ["Invalid or expired token."]}}), 400

    user.set_password(password)
    db.session.commit()

    response = {
        "message": "success",
        "status": 200,
        "data": {
            "message": "Password reset successfully"
        }
    }
    return jsonify(response), 200
