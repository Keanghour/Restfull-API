from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    
    # Register Blueprints
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.user.routes import user_bp
    app.register_blueprint(user_bp)
    
    with app.app_context():
        db.create_all()
    
    return app
