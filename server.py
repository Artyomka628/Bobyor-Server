from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import os
import jwt
import datetime
from functools import wraps
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret')

db = SQLAlchemy(app)

# Настройка лимита запросов
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per hour"])

# Таблица пользователей
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_blocked = db.Column(db.Boolean, default=False)

# Проверка токена для доступа к защищенным маршрутам
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('unauthorized'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return decorated

# Главная страница
@app.route('/')
def home():
    return render_template('index.html')

# Кнопка "Админ панель" ведет на /admin/login
@app.route('/admin/')
def admin_redirect():
    return redirect(url_for('admin_login'))

# Блокировка IP при переборе пароля
blocked_ips = {}

@app.route('/admin/blocked')
def blocked():
    return render_template('blocked.html')

# Страница входа в админ-панель
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    ip = get_remote_address()
    if ip in blocked_ips and (datetime.datetime.utcnow() - blocked_ips[ip]).seconds < 3600:
        return redirect(url_for('blocked'))

    if request.method == 'POST':
        password = request.form.get('password')
        if password == os.getenv('ADMIN_PASSWORD'):
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        blocked_ips[ip] = datetime.datetime.utcnow()
        return redirect(url_for('unauthorized'))

    return render_template('admin_login.html')

# Страница админ-панели (защищенная)
@app.route('/admin/dashboard')
@token_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Страница ошибки доступа
@app.route('/admin/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

# Регистрация пользователя
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"})

# Вход в аккаунт
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.is_blocked:
        return jsonify({"error": "User is blocked"}), 403
    if bcrypt.checkpw(data['password'].encode(), user.password.encode()):
        token = jwt.encode({'user': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
        response = jsonify({"message": "Login successful"})
        response.set_cookie('token', token)
        return response

    return jsonify({"error": "Invalid credentials"}), 401

# Выход из аккаунта
@app.route('/logout')
def logout():
    response = redirect(url_for('home'))
    response.set_cookie('token', '', expires=0)
    return response

# Блокировка пользователя
@app.route('/admin/block_user', methods=['POST'])
@token_required
def block_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user:
        user.is_blocked = True
        db.session.commit()
        return jsonify({"message": "User blocked successfully"})
    return jsonify({"error": "User not found"}), 404

# Разблокировка пользователя
@app.route('/admin/unblock_user', methods=['POST'])
@token_required
def unblock_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user:
        user.is_blocked = False
        db.session.commit()
        return jsonify({"message": "User unblocked successfully"})
    return jsonify({"error": "User not found"}), 404

# Удаление пользователя
@app.route('/admin/delete_user', methods=['DELETE'])
@token_required
def delete_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
