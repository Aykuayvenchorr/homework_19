from flask_restx import Resource, Namespace
from flask import request
from dao.model.user import UserSchema
from implemented import user_service
from service.auth import generate_token, approve_token, generate_password_hash

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        data = request.json
        username = data.get("username")
        password = data.get("password")
        role = data.get("role") or 'other'
        password_hash = generate_password_hash(password)

        if not username or not password:
            return "Нет логина или пароля", 400
        return generate_token(
            username=username,
            password=password,
            password_hash=password_hash,
            role=role,
            is_refresh=False
        ), 201

    def put(self):
        data = request.json
        if not data.get("refresh_token"):
            return "", 400

        return approve_token(data.get("refresh_token")), 200
