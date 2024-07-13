from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token
from datetime import timedelta, datetime
from app.user.models import User_Users, User_Users_log
from app import db

def create_user(data):
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    # Validate required fields
    if not username or not email or not password:
        return jsonify({"message": "Missing required fields"}), 400

    # Check if user already exists
    existing_user = User_Users.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Email address already exists"}), 400

    # Create a new user object
    new_user = User_Users(username=username, email=email, first_name=first_name, last_name=last_name)
    new_user.set_password(password)

    # Add user to database
    db.session.add(new_user)
    db.session.commit()

    # Return success response
    return jsonify({"message": "User created successfully", "user": {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "created_at": new_user.created_at
    }}), 201

def user_login(data):
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    # Query user from database by username or email
    user = User_Users.query.filter((User_Users.username == username) | (User_Users.email == username)).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid username or password"}), 401

    # Generate access token and refresh token
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
    refresh_token = create_refresh_token(identity=user.id)
    expires_in = datetime.utcnow() + timedelta(hours=1)

    # Log the login information
    login_log = User_Users_log(
        user_id=user.id,
        username=user.username,
        email=user.email,
        password_hash=user.password_hash,
        token_type="Bearer",
        access_token=access_token,
        expires_in=expires_in,
        active=True
    )
    db.session.add(login_log)
    db.session.commit()

    # Return tokens and user information
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }), 200

def refresh_token():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id, expires_delta=timedelta(hours=1))

    return jsonify({"access_token": new_access_token}), 200

def user_logout():
    current_user_id = get_jwt_identity()
    
    # Find the log entry for the current user's access token and mark it as inactive
    user_log = User_Users_log.query.filter_by(user_id=current_user_id, active=True).first()
    
    if user_log:
        user_log.active = False
        db.session.commit()
        
    return jsonify({"message": "Successfully logged out"}), 200

def update_user(user_id, data):
    user = User_Users.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Update user fields
    user.email = data.get('email', user.email)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    
    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

def password_reset(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Generate reset token and send email (implementation depends on your email setup)
    reset_token = "generated_reset_token"  # Replace with actual token generation logic
    # send_email(user.email, reset_token)  # Replace with actual email sending logic
    
    return jsonify({"message": "Password reset token sent"}), 200

def password_change(new_password):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    user.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

def verify_email(verification_token):
    user = User.query.filter_by(verification_token=verification_token).first()
    if not user:
        return jsonify({"message": "Invalid or expired token"}), 400
    
    user.is_verified = True
    db.session.commit()
    return jsonify({"message": "Email verified successfully"}), 200

def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200