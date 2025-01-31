﻿from flask import Flask, request, jsonify, render_template, make_response, redirect
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

logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["5 per hour"]
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
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Не указаны имя пользователя или пароль"}), 400

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
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Не указаны имя пользователя или пароль"}), 400

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
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

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
    username = data.get('username')
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    if 'coins' in data: 
        user.coins = int(data['coins'])
    if 'level' in data: 
        user.level = int(data['level'])
    if 'MoneyCountOffline' in data: 
        user.MoneyCountOffline = int(data['MoneyCountOffline'])
    if 'multiplier' in data: 
        user.multiplier = int(data['multiplier'])

    db.session.commit()
    return jsonify({"message": "Данные обновлены"}), 200

@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Не указаны имя пользователя или пароль"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Пользователь уже существует"}), 400
    
    new_user = User(
        username=username,
        password=hash_password(password)
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Пользователь создан администратором"}), 200

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({"error": "Не указано имя пользователя"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Пользователь удалён"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 4096))
    app.run(debug=False, host="0.0.0.0", port=port)
