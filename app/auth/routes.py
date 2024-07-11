from flask import Blueprint, request, jsonify
from .controllers import generate_token, register_user, user_login, request_password_reset, reset_password

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/token', methods=['GET'])
def get_token():
    client_secret = request.args.get('client_secret')
    grant_type = request.args.get('grant_type')
    client_id = request.args.get('client_id')
    response = generate_token(client_secret, grant_type, client_id)
    return jsonify(response)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    return register_user(data)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    return user_login(data)

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    return request_password_reset(data)

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    return reset_password(data)
