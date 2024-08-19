from marshmallow import Schema, fields
from bson.objectid import ObjectId

class User(Schema):
    _id = fields.Str(missing=lambda: str(ObjectId()))
    username = fields.Str()
    email = fields.Str()
    password = fields.Str()
    role = fields.Str()

class BookChapterSchema(Schema):
    _id = fields.Str(missing=lambda: str(ObjectId()))  # unique
    author = fields.Nested(User)
    faculty_name = fields.Str(required=True)
    designation = fields.Str(required=True)
    title_of_chapter = fields.Str(required=True)
    name_of_book = fields.Str(required=True)
    citation_link = fields.Str(required=True)  # unique
    month_and_year = fields.Str(required=True)  # Stores as "MM/YYYY" format
    doi = fields.Str(required=True)  # unique

class ConferenceSchema(Schema):
    _id = fields.Str(missing=lambda: str(ObjectId()))  # unique
    author = fields.Nested(User)
    faculty_name = fields.Str(required=True)
    designation = fields.Str(required=True)
    title_of_paper = fields.Str(required=True)
    citation_link = fields.Str(required=True)  # unique
    month_and_year = fields.Str(required=True)  # Stores as "MM/YYYY" format
    indexing = fields.List(fields.Str(), required=True)
    doi = fields.Str(required=True)  # unique

class JournalSchema(Schema):
    _id = fields.Str(missing=lambda: str(ObjectId()))  # unique
    author = fields.Nested(User)
    faculty_name = fields.Str(required=True)
    designation = fields.Str(required=True)
    title_of_paper = fields.Str(required=True)  # unique
    citation_link = fields.Str(required=True)  # unique
    month_and_year = fields.Str(required=True)  # Stores as "MM/YYYY" format
    indexing = fields.List(fields.Str(), required=True)
    sjr_quartile = fields.Str(required=True)
    doi = fields.Str(required=True)  # unique
