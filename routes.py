from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from marshmallow import ValidationError
import datetime, os
from dotenv import load_dotenv
from db_connection import get_mongo_connection  # Assume this function connects to your MongoDB
from schema import User, JournalSchema, ConferenceSchema, BookChapterSchema
from bson import ObjectId
from functools import wraps

app = Flask(__name__)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)
secret_key = os.environ.get("JWT_SECRET_KEY")
collection0 = get_mongo_connection().users
schema0 = User()

CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config["JWT_SECRET_KEY"] = secret_key
jwt = JWTManager(app)

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('token', None)
        if not token:
            return jsonify({'message': "Token is missing"}), 401
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return func(*args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if not username or not email or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    existing_user = collection0.find_one({"email": email})
    if existing_user:
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = generate_password_hash(password)
    user = {
        "username": username,
        "email": email,
        "password": hashed_password,
        "role": role,
        "created_at": datetime.datetime.utcnow(),
        "updated_at": datetime.datetime.utcnow()
    }

    result = collection0.insert_one(user)
    user['_id'] = str(result.inserted_id)  # Convert ObjectId to string
    user.pop('password')  # Remove password before returning user info
    return jsonify(user), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    user = collection0.find_one({"email": email})
    if user and check_password_hash(user['password'], password):
        token_data = {
            "id": str(user['_id']),
            "role": user['role']
        }
        token = create_access_token(identity=token_data, expires_delta=datetime.timedelta(days=7))
        return jsonify({"token": token})

    return jsonify({"error": "Invalid email or password"}), 404

@app.route('/accounts', methods=['GET'])
@jwt_required()
def accounts():
    current_user = get_jwt_identity()
    user = collection0.find_one({"_id": ObjectId(current_user['id'])})
    if user:
        user.pop('password')  # Remove password before returning user info
        user['_id'] = str(user['_id'])  # Convert ObjectId to string for JSON serialization
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

# BookChapter endpoints
collection1 = get_mongo_connection().BookChapterPublication
schema1 = BookChapterSchema()

@app.route('/api/book/count', methods=['GET'])
def book_count():
    count = collection1.count_documents({})
    return jsonify({"message": count})
@app.route('/api/book_chapter', methods=['OPTIONS', 'POST'])
@jwt_required()
def submit_book_chapter():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight'}), 200

    try:
        current_user = get_jwt_identity()  # Get current user from JWT token
        user_id = current_user['id']
        
        book_data = request.json
        book_data['author'] = {"_id": user_id}  # Set the author field to the current user's ID
        validated_data = schema1.load(book_data)

        existing = collection1.find_one({
            "$or": [
                {"title_of_chapter": validated_data['title_of_chapter']},
                {"name_of_book": validated_data['name_of_book']},
                {"citation_link": validated_data['citation_link']},
                {"doi": validated_data['doi']}
            ]
        })

        same_faculty_book = collection1.find_one({
            "faculty_name": validated_data['faculty_name']
        })

        if existing and same_faculty_book:
            return jsonify({"message": "Book chapter with same name, book title, citation link, or DOI already exists"}), 400

        validated_data['created_at'] = datetime.datetime.utcnow()
        result = collection1.insert_one(validated_data)

        return jsonify({"message": "Publication submitted successfully", "publication_id": str(result.inserted_id)}), 201
    except ValidationError as e:
        return jsonify({"message": "Validation error", "errors": e.messages}), 400
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight'}), 200

    try:
        book_data = request.json
        validated_data = schema1.load(book_data)

        existing = collection1.find_one({
            "$or": [
                {"title_of_chapter": validated_data['title_of_chapter']},
                {"name_of_book": validated_data['name_of_book']},
                {"citation_link": validated_data['citation_link']},
                {"doi": validated_data['doi']}
            ]
        })

        same_faculty_book = collection1.find_one({
            "faculty_name": validated_data['faculty_name']
        })

        if existing and same_faculty_book:
            return jsonify({"message": "Book chapter with same name,book title, citation link, or DOI already exists"}), 400

        validated_data['created_at'] = datetime.datetime.utcnow()
        result = collection1.insert_one(validated_data)

        return jsonify({"message": "Publication submitted successfully", "publication_id": str(result.inserted_id)}), 201
    except ValidationError as e:
        return jsonify({"message": "Validation error", "errors": e.messages}), 400
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/all_book', methods=['GET'])
def all_book_chapters():
    try:
        all_books = list(collection1.find({}))
        if not all_books:
            return jsonify({"message": "No Book chapter found"}), 404
        return jsonify(all_books), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/books/search', methods=['GET'])
def search_books():
    try:
        search_query = request.args.get('q')
        search_filter = {
            "$or": [
                {"_id": {"$regex": search_query, "$options": "i"}},
                {"faculty_name": {"$regex": search_query, "$options": "i"}},
                {"designation": {"$regex": search_query, "$options": "i"}},
                {"title_of_chapter": {"$regex": search_query, "$options": "i"}},
                {"name_of_book": {"$regex": search_query, "$options": "i"}},
                {"citation_link": {"$regex": search_query, "$options": "i"}},
                {"month_and_year": {"$regex": search_query, "$options": "i"}},
                {"doi": {"$regex": search_query, "$options": "i"}}
            ]
        }
        books = list(collection1.find(search_filter))
        if not books:
            return jsonify({"message": "No book details found for the search query"}), 404
        return jsonify(books), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500


@app.route('/api/update_book/<string:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    try:
        # Validate ObjectId
        if not ObjectId.is_valid(book_id):
            return jsonify({"message": "Invalid ObjectId"}), 400

        print(f"Updating book with ID: {book_id}")  # Debug line

        # Fetch the book
        book = collection1.find_one({"_id": ObjectId(book_id)})
        if not book:
            return jsonify({"message": "Book not found"}), 404

        # Proceed with update logic
        book_data = request.get_json()
        result = collection1.find_one_and_update({"_id": ObjectId(book_id)}, {"$set": book_data})

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/delete_book/<string:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    try:
        # Validate ObjectId
        if not ObjectId.is_valid(book_id):
            return jsonify({"message": "Invalid ObjectId"}), 400

        book = collection1.find_one({"_id": ObjectId(book_id)})
        if not book:
            return jsonify({"message": "Book chapter not found"}), 404

        result = collection1.delete_one({"_id": ObjectId(book_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Book chapter deleted successfully"}), 200
        return jsonify({"message": "Failed to delete book chapter"}), 500
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

# Conference endpoints
collection2 = get_mongo_connection().ConferencePublication
schema2 = ConferenceSchema()

@app.route('/api/conference/count', methods=['GET'])
def conference_count():
    count = collection2.count_documents({})
    return jsonify({"message": count})

@app.route('/api/conference', methods=['OPTIONS', 'POST'])
@jwt_required()
def submit_conference():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight'}), 200

    try:
        current_user = get_jwt_identity()  # Get current user from JWT token
        user_id = current_user['id']
        
        conference_data = request.json
        conference_data['author'] = {"_id": user_id}  # Set the author field to the current user's ID
        validated_data = schema2.load(conference_data)

        existing = collection2.find_one({
            "$or": [
                {"title_of_paper": validated_data['title_of_paper']},
                {"citation_link": validated_data['citation_link']},
                {"doi": validated_data['doi']}
            ]
        })

        same_faculty_conference = collection2.find_one({
            "faculty_name": validated_data['faculty_name']
        })

        if existing and same_faculty_conference:
            return jsonify({"message": "Conference paper with same title, citation link, or DOI already exists"}), 400

        validated_data['created_at'] = datetime.datetime.utcnow()
        result = collection2.insert_one(validated_data)

        return jsonify({"message": "Conference submitted successfully", "conference_id": str(result.inserted_id)}), 201
    except ValidationError as e:
        return jsonify({"message": "Validation error", "errors": e.messages}), 400
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/all_conferences', methods=['GET'])
def all_conferences():
    try:
        all_conferences = list(collection2.find({}))
        if not all_conferences:
            return jsonify({"message": "No conference found"}), 404
        return jsonify(all_conferences), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/conference/search', methods=['GET'])
def search_conferences():
    try:
        search_query = request.args.get('q')
        search_filter = {
            "$or": [
                {"_id": {"$regex": search_query, "$options": "i"}},
                {"faculty_name": {"$regex": search_query, "$options": "i"}},
                {"designation": {"$regex": search_query, "$options": "i"}},
                {"title_of_paper": {"$regex": search_query, "$options": "i"}},
                {"citation_link": {"$regex": search_query, "$options": "i"}},
                {"month_and_year": {"$regex": search_query, "$options": "i"}},
                {"indexing": {"$regex": search_query, "$options": "i"}},
                {"doi": {"$regex": search_query, "$options": "i"}}
            ]
        }
        conferences = list(collection2.find(search_filter))
        if not conferences:
            return jsonify({"message": "No conference details found for the search query"}), 404
        return jsonify(conferences), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/delete_conference/<string:conference_id>', methods=['DELETE'])
@jwt_required()
def delete_conference(conference_id):
    try:
        # Validate ObjectId
        if not ObjectId.is_valid(conference_id):
            return jsonify({"message": "Invalid ObjectId"}), 400

        conference = collection2.find_one({"_id": ObjectId(conference_id)})
        if not conference:
            return jsonify({"message": "Conference not found"}), 404

        result = collection2.delete_one({"_id": ObjectId(conference_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Conference deleted successfully"}), 200
        return jsonify({"message": "Failed to delete conference"}), 500
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

# Journal endpoints
collection3 = get_mongo_connection().JournalPublication
schema3 = JournalSchema()

@app.route('/api/journal/count', methods=['GET'])
def journal_count():
    count = collection3.count_documents({})
    return jsonify({"message": count})

@app.route('/api/journal', methods=['OPTIONS', 'POST'])
@jwt_required()
def submit_journal():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight'}), 200

    try:
        current_user = get_jwt_identity()  # Get current user from JWT token
        user_id = current_user['id']
        
        journal_data = request.json
        journal_data['author'] = {"_id": user_id}  # Set the author field to the current user's ID
        validated_data = schema3.load(journal_data)

        existing = collection3.find_one({
            "$or": [
                {"title_of_paper": validated_data['title_of_paper']},
                {"citation_link": validated_data['citation_link']},
                {"doi": validated_data['doi']}
            ]
        })

        same_faculty_journal = collection3.find_one({
            "faculty_name": validated_data['faculty_name']
        })

        if existing and same_faculty_journal:
            return jsonify({"message": "Journal paper with same title, citation link, or DOI already exists"}), 400

        validated_data['created_at'] = datetime.datetime.utcnow()
        result = collection3.insert_one(validated_data)

        return jsonify({"message": "Journal submitted successfully", "journal_id": str(result.inserted_id)}), 201
    except ValidationError as e:
        return jsonify({"message": "Validation error", "errors": e.messages}), 400
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/all_journals', methods=['GET'])
def all_journals():
    try:
        all_journals = list(collection3.find({}))
        if not all_journals:
            return jsonify({"message": "No journal found"}), 404
        return jsonify(all_journals), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/journal/search', methods=['GET'])
def search_journals():
    try:
        search_query = request.args.get('q')
        search_filter = {
            "$or": [
                {"_id": {"$regex": search_query, "$options": "i"}},
                {"faculty_name": {"$regex": search_query, "$options": "i"}},
                {"designation": {"$regex": search_query, "$options": "i"}},
                {"title_of_paper": {"$regex": search_query, "$options": "i"}},
                {"citation_link": {"$regex": search_query, "$options": "i"}},
                {"month_and_year": {"$regex": search_query, "$options": "i"}},
                {"indexing": {"$regex": search_query, "$options": "i"}},
                {"sjr_quartile": {"$regex": search_query, "$options": "i"}},
                {"doi": {"$regex": search_query, "$options": "i"}}
            ]
        }
        journals = list(collection3.find(search_filter))
        if not journals:
            return jsonify({"message": "No journal details found for the search query"}), 404
        return jsonify(journals), 200
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

@app.route('/api/delete_journal/<string:journal_id>', methods=['DELETE'])
@jwt_required()
def delete_journal(journal_id):
    try:
        # Validate ObjectId
        if not ObjectId.is_valid(journal_id):
            return jsonify({"message": "Invalid ObjectId"}), 400

        journal = collection3.find_one({"_id": ObjectId(journal_id)})
        if not journal:
            return jsonify({"message": "Journal not found"}), 404

        result = collection3.delete_one({"_id": ObjectId(journal_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Journal deleted successfully"}), 200
        return jsonify({"message": "Failed to delete journal"}), 500
    except Exception as e:
        return jsonify({"message": "Internal server error", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
