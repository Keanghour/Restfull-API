from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .controllers import create_user, user_login, refresh_token, user_logout
from app.user.models import User_Users

user_bp = Blueprint('user', __name__)

@user_bp.route('/user/register', methods=['POST'])
def create_user_route():
    data = request.get_json()
    return create_user(data)

@user_bp.route('/user/login', methods=['POST'])
def login():
    data = request.get_json()
    return user_login(data)

@user_bp.route('/user/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return refresh_token()

@user_bp.route('/user/logout', methods=['POST'])
@jwt_required()
def logout():
    return user_logout()

@user_bp.route('/user/get-current-user', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User_Users.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "active": user.active
    }), 200

@user_bp.route('/users/list-users', methods=['GET'])
@jwt_required()
def list_users():
    users = User_Users.query.all()
    users_list = [{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "active": user.active
    } for user in users]

    return jsonify(users_list), 200

@user_bp.route('/users/<int:user_id>', methods=['PUT', 'PATCH'])
@jwt_required()
def update_user_route(user_id):
    data = request.get_json()
    return update_user(user_id, data)

@user_bp.route('/users/password-reset', methods=['POST'])
def password_reset_route():
    data = request.get_json()
    username = data.get('username')
    return password_reset(username)

@user_bp.route('/users/password-change', methods=['POST'])
@jwt_required()
def password_change_route():
    data = request.get_json()
    new_password = data.get('new_password')
    return password_change(new_password)

@user_bp.route('/users/verify-email', methods=['GET'])
def verify_email_route():
    verification_token = request.args.get('verification_token')
    return verify_email(verification_token)

@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_route(user_id):
    return delete_user(user_id)