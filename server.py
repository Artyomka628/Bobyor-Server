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
import b2sdk.v2 as b2

# Конфигурация приложения
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")
app.config["B2_KEY_ID"] = os.environ.get("B2_KEY_ID")
app.config["B2_APP_KEY"] = os.environ.get("B2_APP_KEY")
app.config["B2_BUCKET"] = os.environ.get("B2_BUCKET")
app.config["BACKUP_KEY"] = os.environ.get("BACKUP_KEY", Fernet.generate_key())

# Инициализация компонентов
db = SQLAlchemy(app)
fernet = Fernet(app.config["BACKUP_KEY"])
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

# Функции резервного копирования
def backup_db():
    try:
        # Шифрование базы
        with open("accounts.db", "rb") as f:
            encrypted = fernet.encrypt(f.read())
        
        # Подключение к Backblaze
        info = b2.InMemoryAccountInfo()
        b2_api = b2.B2Api(info)
        b2_api.authorize_account("production", app.config["B2_KEY_ID"], app.config["B2_APP_KEY"])
        bucket = b2_api.get_bucket_by_name(app.config["B2_BUCKET"])
        
        # Загрузка файла
        bucket.upload_bytes(
            data_bytes=encrypted,
            file_name="accounts.db.enc"
        )
    except Exception as e:
        app.logger.error(f"Backup error: {str(e)}")

def restore_db():
    try:
        # Восстановление из Backblaze
        info = b2.InMemoryAccountInfo()
        b2_api = b2.B2Api(info)
        b2_api.authorize_account("production", app.config["B2_KEY_ID"], app.config["B2_APP_KEY"])
        bucket = b2_api.get_bucket_by_name(app.config["B2_BUCKET"])
        
        # Скачивание файла
        file_versions = bucket.list_file_versions("accounts.db.enc")
        if file_versions:
            file = file_versions[0]
            downloaded = file.download()
            decrypted = fernet.decrypt(downloaded.get_bytes())
            
            with open("accounts.db", "wb") as f:
                f.write(decrypted)
    except Exception as e:
        app.logger.error(f"Restore error: {str(e)}")

# Инициализация базы при запуске
with app.app_context():
    if not os.path.exists("accounts.db"):
        restore_db()
    db.create_all()

# Хук для автоматического бэкапа
@app.after_request
def auto_backup(response):
    if (
        request.endpoint in ["register", "update_account", "admin_block_user", "admin_delete_user"]
        and response.status_code == 200
    ):
        backup_db()
    return response

# Основные маршруты
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
    
    new_user = User(
        username=username,
        password=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        can_go_leaderboard=True
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Регистрация успешна!"}), 200

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

    # Обновление данных
    if 'coins' in data: 
        user.coins = int(data['coins'])
    if 'level' in data: 
        user.level = int(data['level'])
    if 'multiplier' in data: 
        user.multiplier = int(data['multiplier'])
    if 'can_go_leaderboard' in data: 
        user.can_go_leaderboard = bool(data['can_go_leaderboard'])

    db.session.commit()
    return jsonify({"message": "Данные обновлены"}), 200

# Админские маршруты
def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("admin_token")
        if not token:
            return jsonify({"error": "Требуется авторизация"}), 401
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except:
            return jsonify({"error": "Недействительный токен"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["POST"])
@limiter.limit("10/hour")
def admin_login():
    data = request.get_json()
    password = data.get("password")
    
    if password == os.environ.get("ADMIN_PASSWORD", "1488"):
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        response = make_response(jsonify({"status": "success"}))
        response.set_cookie("admin_token", token, httponly=True, secure=True, samesite="Strict")
        return response
    return jsonify({"error": "Неверный пароль"}), 401

@app.route("/admin/users", methods=["GET"])
@admin_token_required
def get_all_users():
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "coins": u.coins,
        "multiplier": u.multiplier,
        "level": u.level,
        "is_blocked": u.is_blocked,
        "can_go_leaderboard": u.can_go_leaderboard
    } for u in users])

@app.route("/admin/block_user", methods=["POST"])
@admin_token_required
def admin_block_user():
    data = request.json
    username = data.get("username")
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    user.is_blocked = not user.is_blocked
    db.session.commit()
    return jsonify({"message": "Статус блокировки изменён"}), 200

@app.route("/admin/delete_user", methods=["POST"])
@admin_token_required
def admin_delete_user():
    data = request.json
    username = data.get("username")
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Пользователь удалён"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=False, host="0.0.0.0", port=port)
