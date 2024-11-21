import datetime
from functools import wraps
import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger
import os
from dotenv import load_dotenv


# Secret key for encoding and decoding JWT tokens
SECRET_KEY = 'your_secret_key_here'

# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)

# SQL Server configuration from environment variables
driver = os.getenv("SQL_SERVER_DRIVER")
server = os.getenv("SQL_SERVER_HOST")
database = os.getenv("SQL_SERVER_DATABASE")
username = os.getenv("SQL_SERVER_USERNAME")
password = os.getenv("SQL_SERVER_PASSWORD")

# Database connection string
app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc://{username}:{password}@{server}/{database}?driver={driver}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

db = SQLAlchemy(app)

# Initialize Swagger
swagger = Swagger(app, template_file='swagger.json')

# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

# JWT authentication decorator function
def token_required(f):
    """
    Decorator function to protect API routes with JWT token authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Extract token after 'Bearer'

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            # Decode the token
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if current_user is None:
                raise Exception('User not found')

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated_function

# User login route to generate JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Find the user by email (you could also include password check here)
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Create JWT token
    token = jwt.encode(
        {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        SECRET_KEY,
        algorithm='HS256'
    )

    return jsonify({'token': token}), 200

# Create a new user
@app.route('/users', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()
    new_user = User(name=data['name'], email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"}), 201

# Get all users
@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    users = User.query.all()
    users_list = [{"id": user.id, "name": user.name, "email": user.email} for user in users]
    return jsonify(users_list), 200

# Get a single user by ID
@app.route('/users/<int:id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    user = User.query.get(id)
    if user:
        return jsonify({"id": user.id, "name": user.name, "email": user.email}), 200
    return jsonify({"error": "User not found"}), 404

# Update a user by ID
@app.route('/users/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user, id):
    data = request.get_json()
    user = User.query.get(id)
    if user:
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        db.session.commit()
        return jsonify({"message": "User updated successfully!"}), 200
    return jsonify({"error": "User not found"}), 404

# Delete a user by ID
@app.route('/users/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully!"}), 200
    return jsonify({"error": "User not found"}), 404

# Run the Flask application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
