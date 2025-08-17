import os
import ssl
import certifi

# Set SSL certificates before any imports
os.environ['SSL_CERT_FILE'] = certifi.where()
ssl_context = ssl.create_default_context(cafile=certifi.where())
ssl._create_default_https_context = lambda: ssl_context

# Import main application
import rat  # Your rat.py must be in same directory