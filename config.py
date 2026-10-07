"""
config.py — Central configuration for the Cloud Security Scanner app.

WHY THIS FILE EXISTS:
Instead of scattering settings (secret keys, database paths, etc.)
across multiple files, we keep them all here. This makes the app
easier to manage and debug.
"""

import os

# SECRET_KEY is used by Flask to sign session cookies and JWT tokens.
# os.urandom(24) generates a random 24-byte string each time the app starts.
# In production, you'd set this to a fixed value via an environment variable.
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))

# Path to our SQLite database file. It will be created automatically.
DATABASE = 'cloud_scanner.db'

# JWT tokens expire after 24 hours (in seconds: 24 * 60 * 60 = 86400).
JWT_EXPIRATION = 86400

# Where uploaded PDF files are saved.
UPLOAD_FOLDER = 'uploads'
