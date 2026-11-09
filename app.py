
import os
from dotenv import load_dotenv
from flask import Flask, request, render_template_string
from flask_wtf.csrf import CSRFProtect

from config.db import get_db_connection
from routes.admin_routes import admin_bp, admin_dashboard_bp
from routes.auth_routes import auth_bp
from routes.document_routes import document_bp
from routes.dashboard_routes import dashboard_bp

csrf = CSRFProtect()

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

_PRODUCTION_WEAK_SECRET_VALUES = {
    "secret", "change-me", "changeme", "your-secret-key", "dev-secret",
}


def _has_repeated_secret_pattern(secret_bytes):
    return secret_bytes in (secret_bytes + secret_bytes)[1:-1]


def _validate_secret_key(secret_key, environment):
    if isinstance(secret_key, str):
        secret_bytes = secret_key.encode("utf-8")
    elif isinstance(secret_key, bytes):
        secret_bytes = secret_key
    else:
        raise RuntimeError("FLASK_SECRET_KEY must be configured.")

    if not secret_bytes:
        raise RuntimeError("FLASK_SECRET_KEY must be configured.")

    if environment != "development":
        normalized = secret_bytes.decode(
            "utf-8", errors="ignore"
        ).strip().lower()

        if (
            len(secret_bytes) < 32
            or len(secret_bytes) > 4096
            or len(set(secret_bytes)) < 16
            or _has_repeated_secret_pattern(secret_bytes)
            or normalized in _PRODUCTION_WEAK_SECRET_VALUES
        ):
            raise RuntimeError(
                "FLASK_SECRET_KEY is too weak for production."
            )


def create_app(config_override=None):
    """Create TrustVault with an explicitly configured signing key."""
    configuration = dict(config_override or {})

    environment = os.getenv(
        "TRUSTVAULT_ENV", "production"
    ).strip().lower()

    if environment not in {"production", "development", "test"}:
        raise RuntimeError(
            "TRUSTVAULT_ENV must be production, development, or test."
        )

    if configuration.get("TESTING") is True:
        environment = "test"

    secret_key = configuration.get(
        "SECRET_KEY", os.getenv("FLASK_SECRET_KEY")
    )

    secret_bytes = (
        secret_key.encode("utf-8")
        if isinstance(secret_key, str)
        else secret_key if isinstance(secret_key, bytes)
        else b""
    )

    print("SECRET DIAGNOSTIC:", {
        "present": bool(secret_bytes),
        "length": len(secret_bytes),
        "unique_chars": len(set(secret_bytes)),
        "repeated_pattern": (
            _has_repeated_secret_pattern(secret_bytes)
            if secret_bytes else None
        ),
    })

    _validate_secret_key(secret_key, environment)

    application = Flask(__name__)

    application.config.update(
        SECRET_KEY=secret_key,
        UPLOAD_FOLDER=os.path.join(application.root_path, "uploads"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        WTF_CSRF_ENABLED=True,
    )

    application.config.update(configuration)
    csrf.init_app(application)

    @application.after_request
    def prevent_admin_api_caching(response):
        if (
            request.path == "/api/admin"
            or request.path.startswith("/api/admin/")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    application.register_blueprint(auth_bp, url_prefix="/api/auth")
    application.register_blueprint(
        document_bp, url_prefix="/api/documents"
    )
    application.register_blueprint(dashboard_bp)
    application.register_blueprint(admin_bp, url_prefix="/api/admin")
    application.register_blueprint(admin_dashboard_bp)

    @application.route("/")
    def home():
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TrustVault - Secure Document Sharing</title>
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }

                body {
                    font-family: Arial, sans-serif;
                    background: #f1f5f9;
                    color: #172554;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                }

                header {
                    background: #102a56;
                    color: white;
                    padding: 22px 8%;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 15px;
                }

                header h2 {
                    font-size: 25px;
                }

                nav {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }

                nav a, .main-button {
                    text-decoration: none;
                    padding: 12px 22px;
                    border-radius: 7px;
                    font-weight: bold;
                    display: inline-block;
                }

                nav a {
                    color: white;
                    border: 1px solid white;
                }

                nav a:hover {
                    background: white;
                    color: #102a56;
                }

                main {
                    flex: 1;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    text-align: center;
                    padding: 60px 20px;
                }

                .hero {
                    max-width: 750px;
                }

                .hero h1 {
                    font-size: 44px;
                    margin-bottom: 20px;
                    color: #102a56;
                }

                .hero p {
                    font-size: 18px;
                    line-height: 1.7;
                    color: #475569;
                    margin-bottom: 30px;
                }

                .main-button {
                    background: #2563eb;
                    color: white;
                    margin: 8px;
                }

                .main-button.secondary {
                    background: white;
                    color: #2563eb;
                    border: 2px solid #2563eb;
                }

                .main-button:hover {
                    opacity: 0.85;
                }

                footer {
                    text-align: center;
                    padding: 20px;
                    background: #102a56;
                    color: white;
                }

                @media (max-width: 600px) {
                    header {
                        justify-content: center;
                        text-align: center;
                    }

                    .hero h1 {
                        font-size: 32px;
                    }
                }
            </style>
        </head>
        <body>
            <header>
                <h2>TrustVault</h2>
                <nav>
                    <a href="/api/auth/login">Login</a>
                    <a href="/api/auth/register">Register</a>
                </nav>
            </header>

            <main>
                <section class="hero">
                    <h1>TrustVault</h1>
                    <p>
                        Secure Document Sharing with a Real Audit Trail.
                        Protect your documents, manage access permissions,
                        and maintain transparency with secure activity tracking.
                    </p>

                    <a class="main-button"
                       href="/api/auth/register">Get Started</a>

                    <a class="main-button secondary"
                       href="/api/auth/login">Login</a>
                </section>
            </main>

            <footer>
                TrustVault - Secure Document Sharing
            </footer>
        </body>
        </html>
        """)

    @application.route("/test-db")
    def test_db():
        try:
            connection = get_db_connection()
            connection.close()
            return "TrustVault MySQL Connection Successful!"

        except Exception:
            application.logger.exception(
                "TrustVault database connection error"
            )
            return "Database connection failed.", 500

    return application


app = create_app()


def run_server():
    """Run the built-in server without enabling Flask's interactive debugger."""
    app.run(debug=False)


if __name__ == "__main__":
    run_server()
