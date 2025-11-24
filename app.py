from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import mysql.connector

app = Flask(__name__)

# NOTE: For production, these credentials should be stored securely, e.g., in environment variables.
# Since this is a testing environment, we leave them inline as requested.
# However, the security practice of hashing passwords in the database is MANDATORY.
db_config = {
    "host": "centerbeam.proxy.rlwy.net",
    "user": "root",
    "password": "RfddFxxuBtJXmTfoYuGdoVyKWOOlQaiE",
    "database": "secure_crop_db",
    "port": 48054
}

def get_db_connection():
    """Establishes and returns a new database connection."""
    return mysql.connector.connect(**db_config)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user with hashed password and email."""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    # 1. HASH THE PASSWORD
    # This is a critical security step, even for testing!
    password_hash = generate_password_hash(password)
    
    # Use email as a temporary full_name if not provided
    full_name = email.split('@')[0] 
    
    try:
        db = get_db_connection()
        cur = db.cursor()
        
        # Insert user data, using email and password_hash
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, created_at) VALUES (%s, %s, %s, %s)",
            (email, password_hash, full_name, datetime.now())
        )
        db.commit()
        cur.close()
        db.close()
        return jsonify({"message": f"User {email} registered successfully!"}), 201
    except mysql.connector.Error as err:
        # Handle potential errors, e.g., duplicate email (UNIQUE constraint)
        if err.errno == 1062: # MySQL error code for Duplicate entry
             return jsonify({"message": "Registration failed: This email is already in use."}), 409
        print(f"Database error during registration: {err}")
        return jsonify({"message": "A server error occurred during registration."}), 500

@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user by checking email and verifying password hash."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    try:
        db = get_db_connection()
        cur = db.cursor(dictionary=True)
        # 1. Select user by email
        cur.execute("SELECT user_id, email, password_hash, full_name FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        db.close()

        if user:
            # 2. CHECK THE HASHED PASSWORD
            if check_password_hash(user['password_hash'], password):
                # Map DB columns to Frontend expectations
                user_data = {
                    "id": user['user_id'], 
                    "email": user['email'],
                    "name": user['full_name'] or user['email'] # Use full_name if available, otherwise email
                }
                return jsonify({"message": "Login successful!", "user": user_data}), 200
            else:
                # Password incorrect
                return jsonify({"message": "Invalid email or password"}), 401
        else:
            # Email not found
            return jsonify({"message": "Invalid email or password"}), 401
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"message": "Server error during login."}), 500

@app.route('/users', methods=['GET'])
def get_users():
    """Fetches a list of all registered users."""
    try:
        db = get_db_connection()
        cur = db.cursor(dictionary=True)
        # Select key user details only
        cur.execute("SELECT user_id, email, full_name FROM users")
        db_users = cur.fetchall()
        cur.close()
        db.close()
        
        # Map DB columns to Frontend expectations
        users_list = [{
            "id": u['user_id'], 
            "email": u['email'], 
            "name": u['full_name'] or u['email']
        } for u in db_users]
        
        return jsonify(users_list)
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({"message": "Could not retrieve user list."}), 500

@app.route('/pingdb')
def pingdb():
    """Test function to ensure DB connection is alive."""
    try:
        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT 1")
        cur.fetchone() 
        cur.close()
        db.close()
        return "Database connection successful!"
    except Exception as e:
        return f"Database connection failed: {e}"

if __name__ == '__main__':
    # NOTE: Set host='0.0.0.0' for deployment readiness, 
    # but 127.0.0.1 (default) is fine for local testing.
    # The frontend expects the Flask server to be running on http://127.0.0.1:5000.
    app.run(debug=True)