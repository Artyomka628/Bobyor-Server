from flask import Flask, request, jsonify, render_template, make_response, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import os
import jwt
import datetime
import logging
from functools import wraps
from cryptography.fernet import Fernet
import boto3
from botocore.client import Config

# Инициализация приложения
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Конфигурация Backblaze B2
B2_ENDPOINT = os.getenv('B2_ENDPOINT')
B2_ACCESS_KEY = os.getenv('B2_ACCESS_KEY')
B2_SECRET_KEY = os.getenv('B2_SECRET_KEY')
B2_BUCKET = os.getenv('B2_BUCKET')

# Инициализация клиента S3 для Backblaze
s3 = boto3.client(
    's3',
    endpoint_url=B2_ENDPOINT,
    aws_access_key_id=B2_ACCESS_KEY,
    aws_secret_access_key=B2_SECRET_KEY,
    config=Config(signature_version='s3v4')
)

# Конфигурация базы данных
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv('SECRET_KEY')

# Инициализация компонентов
db = SQLAlchemy(app)
fernet = Fernet(os.getenv('BACKUP_KEY').encode())
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["20 per hour"]
)

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    multiplier = db.Column(db.Integer, default=1)
    coins = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    is_blocked = db.Column(db.Boolean, default=False)
    can_go_leaderboard = db.Column(db.Boolean, default=True)

def backup_db():
    """Загрузка базы данных в Backblaze B2"""
    try:
        s3.upload_file('accounts.db', B2_BUCKET, 'accounts.db')
        app.logger.info("Резервная копия создана в B2")
    except Exception as e:
        app.logger.error(f"Ошибка резервного копирования: {str(e)}")

def restore_db():
    """Восстановление базы данных из Backblaze B2"""
    try:
        s3.download_file(B2_BUCKET, 'accounts.db', 'accounts.db')
        app.logger.info("База восстановлена из B2")
    except Exception as e:
        app.logger.error(f"Ошибка восстановления: {str(e)}")
        # Создаем новую базу если файла нет в B2
        with app.app_context():
            db.create_all()

# Инициализация базы при запуске
with app.app_context():
    if not os.path.exists('accounts.db'):
        restore_db()
    else:
        db.create_all()

@app.route("/")
def main_page():
    return render_template("index.html")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Не указаны имя пользователя или пароль"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Пользователь уже существует"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_user = User(username=username, password=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        backup_db()
        return jsonify({"message": "Регистрация успешна!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Ошибка базы данных"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Не указаны имя пользователя или пароль"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
        return jsonify({"error": "Неверное имя пользователя или пароль"}), 401

    return jsonify({
        "username": user.username,
        "multiplier": user.multiplier,
        "coins": user.coins,
        "level": user.level,
        "can_go_leaderboard": user.can_go_leaderboard
    }), 200

@app.route('/update_account', methods=['POST'])
def update_account():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    update_fields = {
        'coins': int,
        'level': int,
        'multiplier': int,
        'can_go_leaderboard': bool
    }

    try:
        for field, converter in update_fields.items():
            if field in data:
                setattr(user, field, converter(data[field]))
        
        db.session.commit()
        backup_db()
        return jsonify({"message": "Данные обновлены"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Ошибка обновления данных"}), 500

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("admin_token")
        if not token:
            return jsonify({"error": "Требуется авторизация"}), 401
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Токен истек"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Недействительный токен"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["POST"])
@limiter.limit("10/hour")
def admin_login():
    data = request.get_json()
    password = data.get("password")
    
    if not password:
        return jsonify({"error": "Не указан пароль"}), 400

    if password == os.getenv("ADMIN_PASSWORD"):
        token_payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(token_payload, app.config["SECRET_KEY"], algorithm="HS256")
        
        response = make_response(jsonify({"status": "success"}))
        response.set_cookie(
            "admin_token",
            token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=3600
        )
        return response
    return jsonify({"error": "Неверный пароль"}), 401

@app.route("/admin/users", methods=["GET"])
@admin_token_required
def get_all_users():
    try:
        users = User.query.all()
        users_data = [{
            "id": user.id,
            "username": user.username,
            "coins": user.coins,
            "level": user.level,
            "multiplier": user.multiplier,
            "is_blocked": user.is_blocked,
            "can_go_leaderboard": user.can_go_leaderboard
        } for user in users]
        return jsonify(users_data), 200
    except Exception as e:
        return jsonify({"error": "Ошибка получения данных"}), 500

@app.route("/admin/block_user", methods=["POST"])
@admin_token_required
def admin_block_user():
    data = request.json
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    try:
        user.is_blocked = not user.is_blocked
        db.session.commit()
        backup_db()
        return jsonify({
            "message": "Статус блокировки изменен",
            "is_blocked": user.is_blocked
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Ошибка обновления"}), 500

@app.route("/admin/delete_user", methods=["POST"])
@admin_token_required
def admin_delete_user():
    data = request.json
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        backup_db()
        return jsonify({"message": "Пользователь удален"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Ошибка удаления"}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Ресурс не найден"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Внутренняя ошибка сервера"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=False, host="0.0.0.0", port=port)
