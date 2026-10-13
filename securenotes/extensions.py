from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["300 per hour"])
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"  # drop the session if the client's IP/user agent changes
