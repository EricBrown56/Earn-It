# chores/firebase_config.py

import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
from dotenv import load_dotenv
import logging # Import logging

# Load environment variables from .env file
load_dotenv()

# Get the path to the service account key from environment variables
# **IMPORTANT**: Make sure the .env file has:
# FIREBASE_SERVICE_ACCOUNT_KEY_PATH='/actual/path/to/your/serviceAccountKey.json'
SERVICE_ACCOUNT_KEY_PATH = os.getenv('FIREBASE_SERVICE_ACCOUNT_KEY_PATH')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variable to track initialization
firebase_initialized = False
db = None # Firestore client
firebase_auth = None # Firebase auth module (will be assigned after init)

# --- Firebase Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK if not already initialized."""
    global firebase_initialized, db, firebase_auth

    if not firebase_initialized:
        if not SERVICE_ACCOUNT_KEY_PATH:
            logger.error("Firebase service account key path not found in environment variables (FIREBASE_SERVICE_ACCOUNT_KEY_PATH).")
            # Set db and auth to None to indicate failure
            db = None
            firebase_auth = None
            # Optionally raise an error or handle differently depending on app requirements
            # raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY_PATH environment variable not set.")
            return # Stop initialization if path is missing

        try:
            # Check if the file exists before trying to load credentials
            if not os.path.exists(SERVICE_ACCOUNT_KEY_PATH):
                 logger.error(f"Service account key file not found at: {SERVICE_ACCOUNT_KEY_PATH}")
                 # Set db and auth to None to indicate failure
                 db = None
                 firebase_auth = None
                 # Optionally raise an error
                 # raise FileNotFoundError(f"Service account key file not found at: {SERVICE_ACCOUNT_KEY_PATH}")
                 return # Stop initialization if file not found

            cred = credentials.Certificate(SERVICE_ACCOUNT_KEY_PATH)
            firebase_admin.initialize_app(cred)
            db = firestore.client() # Get Firestore client
            firebase_auth = auth # Assign auth module from firebase_admin
            firebase_initialized = True
            logger.info("Firebase Admin SDK initialized successfully.")
        except Exception as e:
            logger.error(f"Error initializing Firebase Admin SDK: {e}", exc_info=True)
            # Ensure state reflects failure
            db = None
            firebase_auth = None
            firebase_initialized = False
            # Optionally re-raise the exception if initialization is critical
            # raise e

# --- Firestore Data Structure (Conceptual - Defined in Comments) ---
# /families/{family_id}/
#   - family_name: "The Smiths"
#   - parent_uid: "firebase_auth_uid_of_parent"
#   - created_at: Timestamp

# /users/{user_uid}/  <-- user_uid is the Firebase Auth UID
#   - email: "user@example.com"
#   - display_name: "John Doe"
#   - role: "parent" or "child"
#   - family_id: "family_id_reference"
#   - total_points: 150
#   - created_at: Timestamp

# /chores/{chore_id}/
#   - family_id: "family_id_reference"
#   - name: "Wash Dishes"
#   - description: "Load and run the dishwasher."
#   - points: 10
#   - is_active: true
#   - created_at: Timestamp

# /assigned_chores/{assignment_id}/
#   - chore_id: "chore_id_reference"
#   - user_uid: "child_user_uid_reference" # Who it's assigned to
#   - family_id: "family_id_reference"
#   - assigned_date: Timestamp
#   - due_date: Timestamp (optional)
#   - completed_date: Timestamp (null if not completed)
#   - status: "pending" | "completed" | "verified"
#   - points_awarded: 10 # Points associated with the chore at the time of assignment

# --- Helper Functions ---
def get_user_profile(user_uid):
    """Fetches user profile data from Firestore."""
    if not db:
        logger.warning("Firestore client not available (Firebase not initialized?). Cannot get user profile.")
        return None
    try:
        user_ref = db.collection('users').document(user_uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            return user_doc.to_dict()
        else:
            logger.warning(f"User profile not found in Firestore for UID: {user_uid}")
            return None
    except Exception as e:
        logger.error(f"Error fetching user profile for UID {user_uid}: {e}", exc_info=True)
        return None

# --- Firestore Transaction Helper ---
# This decorator can be used for atomic updates, like adjusting points.
# Example usage is shown in the views.py file.
# from google.cloud.firestore import transactional
# @transactional
# def update_points_transaction(transaction, user_ref, points_change):
#     snapshot = user_ref.get(transaction=transaction)
#     current_points = snapshot.get('total_points') or 0
#     new_total = current_points + points_change
#     transaction.update(user_ref, {'total_points': new_total})
#     return new_total


# Call initialization when this module is imported so db and auth are available
initialize_firebase()
