from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import os
import uuid
import sqlite3
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from argon2 import PasswordHasher

'''
AI acknowledgement:
I used Open AI's ChatGPT as a tool to assist with this assignment.
I used its assistance for guidance on AES encryption,
prompts used:

1. rate limiting using flask limiter
2. JWT token authentication
3. Argon2 password hashing

'''

# Constants
DATABASE = 'totally_not_my_privateKeys.db'
SECRET_KEY = 'your_secret_key'
RATE_LIMIT = "10 per second"

# App Initialization
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], headers_enabled=True)
password_hasher = PasswordHasher()

# Helper Functions
def connect_db():
    return sqlite3.connect(DATABASE)

def execute_query(query, params=()):
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        return cur

def fetch_one(query, params=()):
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchone()

def fetch_all(query, params=()):
    with connect_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()

# JWT Functions
def create_jwt(user_id, is_expired=False):
    expiration = datetime.utcnow() + timedelta(hours=1)
    if is_expired:
        expiration -= timedelta(hours=2)
    payload = {"user_id": user_id, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError as e:
        return {"error": str(e)}

# Database Initialization
def init_database():
    queries = [
        '''CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, key BLOB NOT NULL, exp INTEGER NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS auth_logs (id INTEGER PRIMARY KEY, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))'''
    ]
    for query in queries:
        execute_query(query)

def generate_and_store_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    expiration_time = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    execute_query('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiration_time))

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username, email = data.get('username'), data.get('email')
    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400

    password = str(uuid.uuid4())
    password_hash = password_hasher.hash(password)
    try:
        execute_query('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, password_hash, email))
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409

@app.route('/auth', methods=['POST'])
@limiter.limit(RATE_LIMIT)
def authenticate():
    data = request.json
    username, password = data.get("username"), data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = fetch_one('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    if not user or not password_hasher.verify(user[1], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = create_jwt(user[0])
    execute_query('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request.remote_addr, user[0]))
    return jsonify({"token": token}), 200

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    keys = fetch_all('SELECT id, key FROM keys WHERE exp > ?', (int(datetime.utcnow().timestamp()),))
    jwks = []
    for key_id, key_pem in keys:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        jwks.append({
            "kid": str(key_id),
            "kty": "RSA",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).decode(),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).decode()
        })
    return jsonify({"keys": jwks})

# App Initialization
if __name__ == '__main__':
    init_database()
    generate_and_store_keys()
    app.run(debug=True, port=8080)