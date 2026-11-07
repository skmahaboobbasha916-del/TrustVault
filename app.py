from routes.document_routes import document_bp
from flask import Flask
from config.db import get_db_connection
from routes.auth_routes import auth_bp
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(document_bp, url_prefix="/api/documents")

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