from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os

art = (
    "      ██████████  ██████████  ██████████  ████████    ██████████  ██████████\n"
    "      ██          ██          ██      ██  ██      ██  ██          ██      ██\n"
    "      ██          ██          ██      ██  ██      ██  ██          ██      ██\n"
    "      ██          ██████████  ██████████  ████████    ██████████  ██████████\n"
    "      ██          ██          ██          ██      ██  ██          ██\n"
    "      ██          ██          ██          ██      ██  ██          ██\n"
    "      ██████████  ██████████  ██          ████████    ██████████  ██\n\n"
    "████████       ████     ██████████  ██      ██  ██  ██  ██  ██████████  ██      ██\n"
    "        ██    ██  ██    ██      ██  ██      ██  ██  ██  ██  ██          ██      ██\n"
    "        ██    ██  ██    ██      ██    ██  ██    ██  ██  ██  ██          ██      ██\n"
    "████████     ██    ██   ██      ██      ██      ██  ██  ██  ██████████  ██████████\n"
    "        ██   ████████   ██      ██     ██       ██████████  ██          ██      ██\n"
    "        ██  ██      ██  ██      ██    ██              ███   ██          ██      ██\n"
    "████████    ██      ██  ██      ██   ██                ███  ██████████  ██      ██\n"
    )
print(art)
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Отключаем ASCII-кодирование JSON, чтобы отправлять русские буквы
app.config['JSON_AS_ASCII'] = False

# Настройки базы данных (SQLite)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    multiplier = db.Column(db.Integer, default=1)
    coins = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    MoneyCountOffline = db.Column(db.Integer, default=0)

with app.app_context():
    db.create_all()

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

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

    if 'coins' in data:
        user.coins = data['coins']
    if 'level' in data:
        user.level = data['level']
    if 'MoneyCountOffline' in data:
        user.MoneyCountOffline = data['MoneyCountOffline']
    if 'multiplier' in data:
        user.multiplier = data['multiplier']

    db.session.commit()
    return jsonify({"message": "Данные обновлены"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=True, host="0.0.0.0", port=port)
