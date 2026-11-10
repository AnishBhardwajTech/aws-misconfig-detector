from .api import create_app
from .logging_config import setup_logging

setup_logging()
app = create_app()
