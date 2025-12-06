import os
import sys
from waitress import serve

# Add the project directory to the sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- CONFIGURATION ---
# Change 'YOUR_PROJECT_NAME' to the actual name of your project folder
# (the folder that contains settings.py and wsgi.py)
PROJECT_NAME = "netmon"
PORT = 8080
THREADS = 4

try:
    # This imports the 'application' object from your project's wsgi.py
    from django.core.wsgi import get_wsgi_application

    # Set the default settings module
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"{PROJECT_NAME}.settings")

    # Load the application
    application = get_wsgi_application()

    print(f"Starting Waitress server for {PROJECT_NAME}...")
    print(f"Serving on http://0.0.0.0:{PORT}")
    print(f"Threads: {THREADS}")
    print("Press Ctrl+C to stop.")

    # Start the server
    serve(application, host='0.0.0.0', port=PORT, threads=THREADS)

except ImportError:
    print(f"Error: Could not import 'wsgi.py' from '{PROJECT_NAME}'.")
    print("Please check that the PROJECT_NAME variable in this script matches your project folder name.")
except Exception as e:
    print(f"An error occurred: {e}")