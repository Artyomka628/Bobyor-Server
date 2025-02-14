import os
import datetime
import bcrypt
import jwt
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["20 per hour"])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    blocked = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')

        if not password:
            return jsonify({'error': 'Пароль не передан'}), 400

        admin_pass = os.getenv('ADMIN_PASSWORD')
        print(f"Сохранённый пароль: {admin_pass}")  # Лог для проверки

        if not admin_pass:
            return jsonify({'error': 'ADMIN_PASSWORD не задан в переменных окружения'}), 500

        try:
            # Проверяем, является ли пароль администратора хешированным (если строка длиной 60, это хеш bcrypt)
            if len(admin_pass) == 60:
                if bcrypt.checkpw(password.encode(), admin_pass.encode()):
                    token = jwt.encode({'user': 'admin', 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
                    resp = make_response(redirect(url_for('admin_dashboard')))
                    resp.set_cookie('token', token)
                    return resp
                else:
                    return jsonify({'error': 'Неверный пароль'}), 401
            else:
                # Если пароль не хеширован, хешируем его и сохраняем в переменных окружения
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                os.environ['ADMIN_PASSWORD'] = hashed_password.decode()
                return jsonify({'error': 'Пароль администратора был автоматически хеширован и сохранён'}), 500

        except ValueError:
            return jsonify({'error': 'Пароль администратора в неверном формате! Убедись, что он хеширован в bcrypt'}), 500

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    token = request.cookies.get('token')

    if not token:
        return redirect(url_for('unauthorized'))

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded_token.get('user') != 'admin':
            return redirect(url_for('unauthorized'))
    except jwt.ExpiredSignatureError:
        return redirect(url_for('unauthorized'))
    except jwt.InvalidTokenError:
        return redirect(url_for('unauthorized'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/unauthorized')
def unauthorized():
    return "Доступ запрещён!", 403

@app.route('/admin/blocked')
def blocked():
    return render_template('blocked.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Заполните все поля'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь уже существует'}), 409

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password.decode())
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Регистрация успешна!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
        return jsonify({'error': 'Неверный логин или пароль'}), 401

    if user.blocked:
        return redirect(url_for('blocked'))

    return jsonify({'message': 'Вход успешен!'}), 200

@app.route('/admin/block/<int:user_id>', methods=['POST'])
def block_user(user_id):
    token = request.cookies.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded_token.get('user') != 'admin':
            return jsonify({'error': 'Недостаточно прав'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Недостаточно прав'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    user.blocked = True
    db.session.commit()

    return jsonify({'message': 'Пользователь заблокирован'}), 200

@app.route('/admin/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    token = request.cookies.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded_token.get('user') != 'admin':
            return jsonify({'error': 'Недостаточно прав'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Недостаточно прав'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Пользователь удалён'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
