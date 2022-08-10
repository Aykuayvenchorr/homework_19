from flask import request, current_app
import jwt


def auth_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Bearer ', '')

        if not token:
            raise Exception

        try:
            jwt.decode(token, key=current_app.config['SECRET_KEY'], algorithms=current_app.config['ALGORITHM'])
            return func(*args, **kwargs)

        except Exception:
            raise Exception

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        token = request.headers.environ.get('HTTP_AUTHORIZATION').replace('Bearer ', '')

        if not token:
            raise Exception

        try:
            data = jwt.decode(token, key=current_app.config['SECRET_KEY'], algorithms=current_app.config['ALGORITHM'])
            if data["role"] == 'admin':
                return func(*args, **kwargs)
            else:
                raise Exception

        except Exception:
            raise Exception

    return wrapper
    



