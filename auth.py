"""
auth.py — Authentication routes: Register, Login, Logout.

Uses:
  - bcrypt: to hash passwords (never store plain text!)
  - PyJWT: to create login tokens (JSON Web Tokens)

HOW IT WORKS:
  1. User registers → password is hashed with bcrypt → stored in DB
  2. User logs in → password checked against hash → JWT token created
  3. JWT token stored in a cookie → sent with every request
  4. Protected routes check the token to see who's logged in
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, g
from functools import wraps
import bcrypt
import jwt
import datetime
from config import SECRET_KEY, JWT_EXPIRATION
from database import create_user, get_user_by_email, get_user_by_id

auth_bp = Blueprint('auth', __name__)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def create_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        payload = decode_token(token)
        if not payload:
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

        # Set user in Flask's global context 'g'
        user = get_user_by_id(payload['user_id'])
        if not user:
            flash('User not found. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

        g.user = user
        request.user_id = user['id']
        request.user_role = user['role']

        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if getattr(request, 'user_role', None) not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')

        if get_user_by_email(email):
            flash('An account with this email already exists.', 'danger')
            return render_template('register.html')

        if role not in ('admin', 'auditor', 'user'):
            role = 'user'

        pw_hash = hash_password(password)
        create_user(username, email, pw_hash, role)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')

        user = get_user_by_email(email)

        if not user or not check_password(password, user['password_hash']):
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')

        token = create_token(user['id'], user['role'])
        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie('token', token, httponly=True, max_age=JWT_EXPIRATION)

        flash(f'Welcome back, {user["username"]}!', 'success')
        return response

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    response.delete_cookie('token')
    flash('You have been logged out.', 'info')
    return response
