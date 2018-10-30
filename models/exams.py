from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Exams(db.Model):
    __tablename__ = "exams"
    id = db.Column(db.Integer, primary_key=True)
    type_exams = db.Column(db.Integer)
    subject = db.Column(db.String(225))
    schedule = db.Column(db.DateTime)
    schedule = db.Column(db.String(225))
    status = db.Column(db.Integer)

