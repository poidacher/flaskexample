from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class schedule(db.Model):
    __tablename__ = "schedule"
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Integer)
    subject = db.Column(db.String(225))
    schedule = db.Column(db.String(225))
    answer_one = db.Column(db.String(225))
    answer_two = db.Column(db.String(225))
    answer_three = db.Column(db.String(225))
    public_answer_one = db.Column(db.String(225))
    public_answer_two = db.Column(db.String(225))
    public_answer_three = db.Column(db.String(225))
    answer = db.Column(db.String(225))
    public_question = db.Column(db.String(225))

