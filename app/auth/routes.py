from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import get_jwt_identity, jwt_required
from .controllers import refresh_access_token
from .controllers import generate_token, refresh_access_token, register_user, resend_otp, user_login, request_password_reset, reset_password as reset_password_controller, verify_otp

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/token', methods=['GET'])
def get_token():
    client_secret = request.args.get('client_secret')
    grant_type = request.args.get('grant_type')
    client_id = request.args.get('client_id')
    
    if not client_secret or not grant_type or not client_id:
        abort(400, description="Missing required parameters: client_secret, grant_type, client_id")

    response = generate_token(client_secret, grant_type, client_id)
    return jsonify(response)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "error", "status": 400, "data": {"error": "Missing required JSON data: username, password"}}), 400
    
    return register_user(data)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        abort(400, description="Missing required JSON data: username, password")
    
    return user_login(data)

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or not data.get('email'):
        abort(400, description="Missing required JSON data: email")
    
    return request_password_reset(data)

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('password_confirmation') or not data.get('password_token'):
        abort(400, description="Missing required JSON data: email, password, password_confirmation, password_token")
    
    return reset_password_controller(data)

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp_route():
    data = request.get_json()
    if not data or not data.get('email'):
        abort(400, description="Missing required JSON data: email")
    
    return resend_otp(data)

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('otp_code'):
        abort(400, description="Missing required JSON data: email, otp_code")
    
    return verify_otp(data)


@auth_bp.route('/refresh-token', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    data = request.get_json()
    if not data or not data.get('refresh_token'):
        abort(400, description="Missing required JSON data: refresh_token")

    # Call a function from controllers.py to handle refresh token logic
    response = refresh_access_token(data)

    # Assuming `refresh_access_token` returns a dictionary or JSON serializable object
    return jsonify(response)


