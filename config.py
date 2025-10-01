import os
from flask.cli import load_dotenv

load_dotenv()
SECRET_KEY = os.environ.get('SECRET_KEY')