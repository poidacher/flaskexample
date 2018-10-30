from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Type(db.Model):
    __tablename__ = "type"
    id = db.Column(db.Integer, primary_key=True)
    name_type = db.Column(db.String(225))
    description = db.Column(db.String(225))
    participants = db.Column(db.Integer)
    status = db.Column(db.Integer)
