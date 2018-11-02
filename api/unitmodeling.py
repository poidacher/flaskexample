from . import db


class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(225), unique=True)
    password = db.Column(db.String(225))
    public_id = db.Column(db.String(225), unique=True)
    admin = db.Column(db.Integer)
    name = db.Column(db.String(225))
