from flask import Flask
app = Flask(__name__)


from flask_sqlalchemy import SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from api.UserController import poi_user
app.register_blueprint(poi_user, url_prefix="/oak")
