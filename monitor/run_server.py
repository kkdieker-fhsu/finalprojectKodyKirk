import os, sys
from waitress import serve

#add the project directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

#initial variables
PROJECT_NAME = "netmon"
PORT = 8080
THREADS = 4

try:
    #import wsgi application
    from django.core.wsgi import get_wsgi_application

    #use django settings
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"{PROJECT_NAME}.settings")

    application = get_wsgi_application()

    print(f"Starting Waitress server for {PROJECT_NAME}...")
    print(f"Serving on http://0.0.0.0:{PORT}")
    print(f"Threads: {THREADS}")
    print("Press Ctrl+C to stop.")

    #start the server
    serve(application, host='0.0.0.0', port=PORT, threads=THREADS)

except ImportError:
    print(f"Error: Could not import 'wsgi.py' from '{PROJECT_NAME}'.")
    print("Please check that the PROJECT_NAME variable in this script matches your project folder name.")
except Exception as e:
    print(f"An error occurred: {e}")