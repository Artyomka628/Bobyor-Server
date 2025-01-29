from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import jwt
import datetime
from functools import wraps

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
CORS(app, supports_credentials=True)  # Разрешаем запросы с других сайтов

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///accounts.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"  # Ключ для подписи JWT токена

db = SQLAlchemy(app)

# Админский пароль (замени на свой!)
ADMIN_PASSWORD = "admin123"

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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return jsonify({"error": "Требуется авторизация"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except:
            return jsonify({"error": "Недействительный токен"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def admin_panel():
    return render_template("admin_panel.html")

@app.route("/admin_login", methods=["POST"])
def admin_login():
    data = request.json
    password = data.get("password")
    if password == ADMIN_PASSWORD:
        token = jwt.encode({
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config["SECRET_KEY"], algorithm="HS256")
        response = make_response(jsonify({"message": "Вход выполнен"}))
        response.set_cookie("token", token, httponly=True)
        return response
    return jsonify({"error": "Неверный пароль"}), 401

@app.route("/get_users", methods=["GET"])
@token_required
def get_users():
    users = User.query.all()
    return jsonify([{ "id": u.id, "username": u.username, "coins": u.coins, "level": u.level, "blocked": u.is_blocked } for u in users])

@app.route("/block_user", methods=["POST"])
@token_required
def block_user():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()
    if user:
        user.is_blocked = True
        db.session.commit()
        return jsonify({"message": "Пользователь заблокирован"})
    return jsonify({"error": "Пользователь не найден"}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=True, host="0.0.0.0", port=port)
