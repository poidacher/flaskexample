from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class ScheduleTypeMapping(db.Model):
    __tablename__ = "schedule_type_mapping"
    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer)
    type_id = db.Column(db.Integer)
    status = db.Column(db.Integer)


class TypeExamsMapping(db.Model):
    __tablename__ = "type_exams_mapping"
    id = db.Column(db.Integer, primary_key=True)
    exams_id = db.Column(db.Integer)
    type_id = db.Column(db.Integer)
    status = db.Column(db.Integer)
