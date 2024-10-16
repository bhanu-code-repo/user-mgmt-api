# api/user_routes.py
from flask import Blueprint, request, jsonify
from bson import ObjectId
from db.db import MongoDB
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
from flasgger import swag_from

user_bp = Blueprint('user', __name__)

# Get the MongoDB instance
db = MongoDB().get_db()
users_collection = db["users"]

# Allowed roles
ALLOWED_ROLES = ["user", "admin", "expert", "virtual assistant"]

# Validate email format
def is_valid_email(email):
    return re.match(r"^[\w\.-]+@pbus\.com$", email)

# Create a user
@user_bp.route('/users', methods=['POST'])
@swag_from({
    'responses': {
        201: {'description': 'User created successfully'},
        400: {'description': 'Invalid input or missing fields'}
    },
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'description': 'User information',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'john@pbus.com'},
                    'password': {'type': 'string', 'example': 'password123'},
                    'role': {'type': 'string', 'enum': ALLOWED_ROLES, 'example': 'admin'},
                    'active': {'type': 'boolean', 'example': True},
                    'department': {'type': 'string', 'example': 'IT'},
                    'domain': {'type': 'string', 'example': 'tech'}
                }
            }
        }
    ]
})
def create_user():
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get("username") or not data.get("password") or not data.get("role"):
        return jsonify({"error": "Username, password, and role are required!"}), 400
    
    # Check if email is in the correct format
    if not is_valid_email(data["username"]):
        return jsonify({"error": "Email must be in @pbus.com format"}), 400
    
    # Hash the password
    hashed_password = generate_password_hash(data["password"])
    
    # Check if role is valid
    if data["role"] not in ALLOWED_ROLES:
        return jsonify({"error": "Invalid role. Allowed roles are 'user', 'admin', 'expert', 'virtual assistant'"}), 400
    
    # Create user object
    user = {
        "username": data["username"],
        "password": hashed_password,
        "role": data["role"],
        "active": data.get("active", True),
        "department": data.get("department", None),
        "domain": data.get("domain", None),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    
    # Insert the user
    result = users_collection.insert_one(user)
    
    return jsonify({"message": "User created", "id": str(result.inserted_id)}), 201


# Get all users
@user_bp.route('/users', methods=['GET'])
@swag_from({
    'responses': {
        200: {
            'description': 'A list of users',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'string'},
                        'username': {'type': 'string'},
                        'role': {'type': 'string'},
                        'active': {'type': 'boolean'},
                        'department': {'type': 'string'},
                        'domain': {'type': 'string'},
                        'created_at': {'type': 'string'},
                        'updated_at': {'type': 'string'}
                    }
                }
            }
        }
    }
})
def get_users():
    users = users_collection.find()
    user_list = [{
        "id": str(user["_id"]),
        "username": user["username"],
        "role": user["role"],
        "active": user["active"],
        "department": user.get("department"),
        "domain": user.get("domain"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at")
    } for user in users]
    return jsonify(user_list), 200


# Get user by ID
@user_bp.route('/users/<user_id>', methods=['GET'])
@swag_from({
    'parameters': [
        {
            'name': 'id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'User ID',
            'example': '615d1f1b6c9f1c23456789ab'
        }
    ],
    'responses': {
        200: {
            'description': 'User information',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'example': '615d1f1b6c9f1c23456789ab'},
                    'username': {'type': 'string', 'example': 'john@pbus.com'},
                    'role': {'type': 'string', 'example': 'admin'},
                    'active': {'type': 'boolean', 'example': True},
                    'department': {'type': 'string', 'example': 'IT'},
                    'domain': {'type': 'string', 'example': 'tech'},
                    'created_at': {'type': 'string', 'example': '2023-10-16T12:45:23.123Z'},
                    'updated_at': {'type': 'string', 'example': '2023-10-16T12:45:23.123Z'}
                }
            }
        },
        404: {'description': 'User not found'}
    }
})
def get_user(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        user_data = {
            "id": str(user["_id"]),
            "username": user["username"],
            "role": user["role"],
            "active": user["active"],
            "department": user.get("department"),
            "domain": user.get("domain"),
            "created_at": user.get("created_at"),
            "updated_at": user.get("updated_at")
        }
        return jsonify(user_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Update user by ID
@user_bp.route('/users/<user_id>', methods=['PUT'])
@swag_from({
    'parameters': [
        {
            'name': 'id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'User ID',
            'example': '615d1f1b6c9f1c23456789ab'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'description': 'Updated user information',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'john@pbus.com'},
                    'password': {'type': 'string', 'example': 'new_password123'},
                    'role': {'type': 'string', 'enum': ALLOWED_ROLES, 'example': 'admin'},
                    'active': {'type': 'boolean', 'example': True},
                    'department': {'type': 'string', 'example': 'HR'},
                    'domain': {'type': 'string', 'example': 'human resources'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'User updated successfully'},
        404: {'description': 'User not found'}
    }
})
def update_user(user_id):
    data = request.get_json()
    update_data = {}
    
    if "username" in data:
        if not is_valid_email(data["username"]):
            return jsonify({"error": "Email must be in @pbus.com format"}), 400
        update_data["username"] = data["username"]
    
    if "password" in data:
        update_data["password"] = generate_password_hash(data["password"])
    
    if "role" in data:
        if data["role"] not in ALLOWED_ROLES:
            return jsonify({"error": "Invalid role. Allowed roles are 'user', 'admin', 'expert', 'virtual assistant'"}), 400
        update_data["role"] = data["role"]
    
    if "active" in data:
        update_data["active"] = data["active"]
    
    if "department" in data:
        update_data["department"] = data["department"]
    
    if "domain" in data:
        update_data["domain"] = data["domain"]
    
    update_data["updated_at"] = datetime.utcnow()

    result = users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"message": "User updated"}), 200


# Delete user by ID
@user_bp.route('/users/<user_id>', methods=['DELETE'])
@swag_from({
    'parameters': [
        {
            'name': 'id',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'User ID',
            'example': '615d1f1b6c9f1c23456789ab'
        }
    ],
    'responses': {
        200: {'description': 'User deleted successfully'},
        404: {'description': 'User not found'}
    }
})
def delete_user(user_id):
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "User deleted"}), 200

# Login (Authenticate User)
@user_bp.route('/login', methods=['POST'])
@swag_from({
    'responses': {
        200: {'description': 'Login successful'},
        400: {'description': 'Invalid username or password'},
        404: {'description': 'User not found'},
        401: {'description': 'Invalid password'}
    },
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'description': 'Login credentials',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'john@pbus.com'},
                    'password': {'type': 'string', 'example': 'password123'}
                }
            }
        }
    ]
})
def login_user():
    data = request.get_json()

    # Validate required fields
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required!"}), 400

    # Check if email is in the correct format
    if not is_valid_email(data["username"]):
        return jsonify({"error": "Email must be in @pbus.com format"}), 400

    # Find the user by username (email)
    user = users_collection.find_one({"username": data["username"]})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check if the password is correct
    if not check_password_hash(user["password"], data["password"]):
        return jsonify({"error": "Invalid password"}), 401

    # If authenticated, return user info (excluding password)
    user_data = {
        "id": str(user["_id"]),
        "username": user["username"],
        "role": user["role"],
        "active": user["active"],
        "department": user.get("department"),
        "domain": user.get("domain"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at")
    }

    return jsonify({"message": "Login successful", "user": user_data}), 200
