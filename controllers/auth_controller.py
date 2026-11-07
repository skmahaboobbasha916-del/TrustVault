from models.user_model import create_user, get_user_by_email
from werkzeug.security import check_password_hash


def register_user(name, email, password):
    if get_user_by_email(email):
        return False, "Email already registered."

    create_user(name, email, password)
    return True, "Registration successful."


def authenticate_user(email, password):
    user = get_user_by_email(email)

    if user and check_password_hash(user["password"], password):
        return user

    return None