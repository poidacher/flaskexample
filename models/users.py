from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Users(db.Model):
    __tablename_="users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(225), unique=True)
    password = db.Column(db.String(225))
    public_id = db.Column(db.String(225))
    admin = db.Column(db.Boolean)
    name = db.Column(db.String(225))
