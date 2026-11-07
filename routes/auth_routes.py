from flask import Blueprint, request, jsonify, session, render_template
from controllers.auth_controller import register_user, authenticate_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not email or not password:
        return "All fields are required.", 400

    if len(password) < 8:
        return "Password must be at least 8 characters.", 400

    try:
        success, message = register_user(name, email, password)

        if not success:
            return message, 409

        return "Registration successful! You can now log in.", 201

    except Exception:
        return "Registration failed.", 500

@auth_bp.route("/login", methods=["POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return "Email and password are required.", 400

    user = authenticate_user(email, password)

    if not user:
        return "Invalid email or password.", 401

    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    return "Login successful!", 200

@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."}), 200