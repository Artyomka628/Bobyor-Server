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

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# Инициализация лимитера с хранилищем в памяти
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["5 per hour"]  # Общий лимит
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    multiplier = db.Column(db.Integer, default=1)
    coins = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    MoneyCountOffline = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

ADMIN_PASSWORD = "1488"

# ===================== ОСНОВНЫЕ ФУНКЦИИ =====================
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

@app.route("/")
def main_page():
    return render_template("index.html")

@app.route('/delete_db', methods=['GET'])
def delete_db():
    try:
        os.remove("accounts.db")
        return jsonify({"message": "База данных удалена"}), 200
    except FileNotFoundError:
        return jsonify({"error": "Файл не найден"}), 404

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Пользователь уже существует"}), 400
    
    new_user = User(
        username=username,
        password=hash_password(password)
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Регистрация успешна!"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return jsonify({"error": "Неверное имя пользователя или пароль"}), 401

    return jsonify({
        "username": user.username,
        "multiplier": user.multiplier,
        "coins": user.coins,
        "level": user.level,
        "MoneyCountOffline": user.MoneyCountOffline
    }), 200

@app.route('/get_account', methods=['GET'])
def get_account():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    return jsonify({
        "username": user.username,
        "multiplier": user.multiplier,
        "coins": user.coins,
        "level": user.level,
        "MoneyCountOffline": user.MoneyCountOffline
    }), 200

@app.route('/update_account', methods=['POST'])
def update_account():
    data = request.json
    username = data['username']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    if 'coins' in data: user.coins = data['coins']
    if 'level' in data: user.level = data['level']
    if 'MoneyCountOffline' in data: user.MoneyCountOffline = data['MoneyCountOffline']
    if 'multiplier' in data: user.multiplier = data['multiplier']

    db.session.commit()
    return jsonify({"message": "Данные обновлены"}), 200

# ===================== АДМИН-ПАНЕЛЬ =====================
def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("admin_token")
        if not token:
            app.logger.warning("Попытка доступа без токена")
            return jsonify({"error": "Требуется авторизация"}), 401
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            app.logger.warning("Истек срок действия токена")
            return jsonify({"error": "Токен устарел"}), 401
        except Exception as e:
            app.logger.error(f"Недействительный токен: {str(e)}")
            return jsonify({"error": "Недействительный токен"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["POST"])
@limiter.limit("5/hour", override_defaults=False, deduct_when=lambda response: response.status_code != 200)
def admin_login():
    try:
        data = request.get_json()
        if not data:
            app.logger.error("Неверный формат запроса")
            return jsonify({"status": "invalid_request"}), 400

        password = data.get("password")
        app.logger.debug(f"Попытка входа с паролем: {password}")

        if password == ADMIN_PASSWORD:
            token = jwt.encode(
                payload={
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                },
                key=app.config["SECRET_KEY"],
                algorithm="HS256"
            )
            response = make_response(jsonify({"status": "success"}))
            response.set_cookie(
                "admin_token",
                token,
                httponly=True,
                secure=True,
                samesite="Strict",
                max_age=3600
            )
            app.logger.info("Успешная аутентификация")
            return response
        else:
            app.logger.warning("Неверный пароль")
            # Явно уменьшаем счетчик попыток
            limiter.hit(request.endpoint, request.view_args)
            return jsonify({"status": "invalid_password"}), 401

    except Exception as e:
        app.logger.critical(f"Ошибка сервера: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

# ... (остальные маршруты без изменений) ...

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=False, host="0.0.0.0", port=port)
