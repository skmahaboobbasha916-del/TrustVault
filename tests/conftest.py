import os


# Explicit test-only app configuration; never used as a production fallback.
os.environ["TRUSTVAULT_ENV"] = "test"
os.environ["FLASK_SECRET_KEY"] = "trustvault-pytest-signing-key-not-for-production-2026"
