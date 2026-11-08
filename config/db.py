import os
import pymysql
from dotenv import load_dotenv


load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "trustvault"),
        cursorclass=pymysql.cursors.DictCursor,
        init_command="SET time_zone = '+00:00'",
    )
