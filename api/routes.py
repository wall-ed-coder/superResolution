from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import request, jsonify, make_response
from flask_restx import Api, Resource, fields

import jwt

from .models import db, UsersSecret, JWTTokenBlocklist, NotAuthorisedDownloadsAmount, AmountFreeDownloads
from .config import BaseConfig

rest_api = Api(version="1.0", title="UsersSecret API")

"""
    Flask-Restx models for api request and response data
"""

signup_model = rest_api.model('SignUpModel', {"username": fields.String(required=True, min_length=2, max_length=32),
                                              "email": fields.String(required=True, min_length=4, max_length=64),
                                              "password": fields.String(required=True, min_length=4, max_length=16)
                                              })

login_model = rest_api.model('LoginModel', {"email": fields.String(required=True, min_length=4, max_length=64),
                                            "password": fields.String(required=True, min_length=4, max_length=16)
                                            })

user_edit_model = rest_api.model('UserEditModel', {"userID": fields.String(required=True, min_length=1, max_length=32),
                                                   "username": fields.String(required=True, min_length=2,
                                                                             max_length=32),
                                                   "email": fields.String(required=True, min_length=4, max_length=64)
                                                   })

"""
   Helper function for JWT token required
"""


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            data = jwt.decode(token, BaseConfig.SECRET_KEY, algorithms=["HS256"])
            current_user = UsersSecret.get_by_email(data["email"])

            if not current_user:
                return {"success": False,
                        "msg": "Sorry. Wrong auth token. This user does not exist."}, 400

            token_expired = db.session.query(JWTTokenBlocklist.id).filter_by(jwt_token=token).scalar()

            if token_expired is not None:
                return {"success": False, "msg": "Token revoked."}, 400

            if not current_user.check_jwt_auth_active():
                return {"success": False, "msg": "Token expired."}, 400

        except:
            return {"success": False, "msg": "Token is invalid"}, 400

        return f(current_user, *args, **kwargs)

    return decorator


"""
    Flask-Restx routes
"""


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """

    @rest_api.expect(signup_model, validate=True)
    def post(self):
        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = UsersSecret.get_by_email(_email)
        if user_exists:
            return {"success": False,
                    "msg": "Email already taken"}, 400

        new_user = UsersSecret(username=_username, email=_email)

        new_user.set_password(_password)
        new_user.save()

        return {"success": True,
                "userID": new_user.id,
                "msg": "The user was successfully registered"}, 200


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):

        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = UsersSecret.get_by_email(_email)

        if not user_exists:
            return {"success": False,
                    "msg": "This email does not exist."}, 400

        if not user_exists.check_password(_password):
            return {"success": False,
                    "msg": "Wrong credentials."}, 400

        # create access token uwing JWT
        token = jwt.encode({'email': _email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, BaseConfig.SECRET_KEY)

        user_exists.set_jwt_auth_active(True)
        user_exists.save()

        return {"success": True,
                "token": token,
                "user": user_exists.toJSON()}, 200


@rest_api.route('/api/users/edit')
class EditUser(Resource):
    """
       Edits User's username or password or both using 'user_edit_model' input
    """

    @rest_api.expect(user_edit_model)
    @token_required
    def post(self, current_user):

        req_data = request.get_json()

        _new_username = req_data.get("username")
        _new_email = req_data.get("email")

        if _new_username:
            self.update_username(_new_username)

        if _new_email:
            self.update_email(_new_email)

        self.save()

        return {"success": True}, 200


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    """
       Logs out User using 'logout_model' input
    """

    @token_required
    def post(self, current_user):
        _jwt_token = request.headers["authorization"]

        jwt_block = JWTTokenBlocklist(jwt_token=_jwt_token, created_at=datetime.now(timezone.utc))
        jwt_block.save()

        self.set_jwt_auth_active(False)
        self.save()

        return {"success": True}, 200


@rest_api.route('/api/users/checkToken')
class CheckUserAuth(Resource):
    @token_required
    def post(self, current_user):
        _jwt_token = request.headers["authorization"]
        return {"success": True}, 200


@rest_api.route('/api/checkUploadsAmount')
class CheckUploadsAmount(Resource):
    def get(self):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        db.session.query(NotAuthorisedDownloadsAmount).filter(NotAuthorisedDownloadsAmount.date_created <= cutoff).delete()
        idx_ip = NotAuthorisedDownloadsAmount.get_by_ip(request.remote_addr)
        if len(idx_ip) == 0:
            new_ip = NotAuthorisedDownloadsAmount(amount=AmountFreeDownloads.get_amount(),
                                                  date_created=datetime.now(timezone.utc), ip_user=request.remote_addr)
            new_ip.save()
            return {"success": True,
                    "msg": 'Row was created successfully!'}, 200
        else:
            if idx_ip[0].amount == 0:
                return {"success": False,
                        "msg": "Your available amount of downloads was ended", "cutoff": str(cutoff)}, 200
            elif idx_ip[0].amount > 0:
                ip_string = idx_ip[0]
                ip_string.amount = ip_string.amount - 1
                db.session.commit()
                return {"success": True,
                        "msg": "Your image was uploaded"}
