
from flask import Flask
from config.db import get_db_connection
from routes.auth_routes import auth_bp
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.register_blueprint(auth_bp, url_prefix="/api/auth")


@app.route("/")
def home():
    return "TrustVault - Secure Document Sharing"


@app.route("/test-db")
def test_db():
    try:
        connection = get_db_connection()
        connection.close()
        return "TrustVault MySQL Connection Successful!"
    except Exception:
        return "Database connection failed.", 500


if __name__ == "__main__":
    app.run(debug=True)