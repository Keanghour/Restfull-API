import random
import string
import re
from flask import current_app, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from .models import auth_User, auth_UserLogin, auth_TokenRequestLog, auth_OTP
from app import db


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
    return auth_User.query.filter_by(email=email).first()

def request_password_reset(data):
    email = data.get('email')
    user = auth_User.query.filter_by(email=email).first()
    if user:
        otp_code = generate_otp()
        token = generate_reset_token(user)
        expires_at = datetime.utcnow() + timedelta(hours=7)

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
    token_type = "bearer" 

    # Log token request
    token_log = auth_TokenRequestLog.query.filter_by(access_token=access_token).first()
    if token_log:
        token_log.increment_request_count()
    else:
        token_log = auth_TokenRequestLog(token_type=token_type, access_token=access_token)
        db.session.add(token_log)
    db.session.commit()

    refresh_token = create_access_token(identity=client_id, additional_claims=additional_claims)

    response = {
        "data": {
            "jwt": {
                "access_token": access_token,
                "expires_in": 3600,  # Assuming access token expires in 1 hour
                "token_type": token_type,
                "refresh_token": refresh_token  # Add the refresh token to the response
            }
        },
        "message": "success",
        "status": 200
    }
    return response

def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email)

def register_user(data):
    full_name = data.get('full_name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    password_confirmation = data.get('password_confirmation')

    if not is_valid_email(email):
        return jsonify({"message": "error", "status": 422, "data": {"email": ["Invalid email address."]}}), 422

    if password != password_confirmation:
        return jsonify({"message": "error", "status": 422, "data": {"password": ["Passwords do not match."]}}), 422

    existing_user = auth_User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({"message": "error", "status": 422, "data": {"email": ["The email has already been taken."]}}), 422

    new_user = auth_User(full_name=full_name, email=email, username=username)
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

    user = auth_User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid username or password", "status": 401}), 401

    # Generate JWT tokens
    access_token = create_access_token(
        identity=user.username,
        additional_claims={
            'full_name': user.full_name,
            'username': user.username
        },
        expires_delta=timedelta(hours=7)
    )

    refresh_token = create_refresh_token(identity=user.username)

    # Save the login details
    login_entry = auth_UserLogin(
        username=user.username,
        email=user.email,
        access_token=access_token,
        expires_in=3600,  # This should match the actual expiration of the access token
        token_type="bearer",  # Assuming bearer token type for this example
        status_code=200
    )
    db.session.add(login_entry)
    db.session.commit()

    response = {
        "message": "success",
        "status": 200,
        "data": {
            "jwt": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": 3600  # This should match the actual expiration of the access token
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

def resend_otp(data):
    email = data.get('email')
    user = auth_User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"message": "error", "status": 404, "data": {"email": ["User not found."]}}), 404
    
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    otp_entry = auth_OTP(user_id=user.id, email = email, otp_code=otp_code, expires_at=expires_at, payload_resend={
        "message": "success",
        "status": 200,
        "data": {
            "message": "OTP code sent successfully, Please check your email",
            "expires_at": expires_at.isoformat() + 'Z',
            "otp_code": otp_code
        }
    })
    db.session.add(otp_entry)
    db.session.commit()
    
    response_data = otp_entry.payload_resend
    return jsonify(response_data), 200

def verify_otp(data):
    email = data.get('email')
    otp_code = data.get('otp_code')

    user = auth_User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "error", "status": 404, "data": {"email": ["User not found."]}}), 404

    otp_entry = auth_OTP.query.filter_by(user_id=user.id, otp_code=otp_code).order_by(auth_OTP.created_at.desc()).first()
    if not otp_entry:
        return jsonify({"message": "error", "status": 400, "data": {"otp_code": ["Invalid OTP code."]}}), 400

    success, message = otp_entry.verify(otp_code)
    if not success:
        return jsonify({"message": "error", "status": 400, "data": {"otp_code": [message]}}), 400

    response_data = otp_entry.payload_verify
    return jsonify(response_data), 200

def refresh_access_token(data):
    refresh_token = data.get('refresh_token')

    # Example logic to generate new access token
    new_access_token = generate_new_access_token(refresh_token)

    response = {
        "message": "success",
        "status": 200,
        "data": {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 3600  # Example expiry time in seconds
        }
    }
    return response

def generate_new_access_token(refresh_token):
    # Example logic to generate a new access token based on the refresh token
    # Replace this with your actual implementation
    new_access_token = create_access_token(identity="example_identity")
    return new_access_token
