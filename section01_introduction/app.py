from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from db import db
from blocklist import BLOCKLIST
from resources.user import UserRegister, UserLogin, User, TokenRefresh, UserLogout
from resources.store import Store, StoreList
from resources.item import Item, ItemList


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "luis_melendez" 
api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()

jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in BLOCKLIST

api.add_resource(TokenRefresh, "/refresh")
api.add_resource(UserLogout, "/logout")

api.add_resource(Store, "/store/<string:name>")
api.add_resource(StoreList, "/stores")

api.add_resource(Item, "/item/<string:name>")
api.add_resource(ItemList, "/items")

api.add_resource(UserRegister, "/register")
api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserLogin, "/login")


if __name__ == "__main__":
    db.init_app(app)
    app.run(port=5000, debug=True)
