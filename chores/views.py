# chores/views.py

from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponseForbidden, JsonResponse, HttpResponseBadRequest, Http404, HttpResponseServerError
from django.views import View
from django.contrib import messages # For flash messages
from .firebase_config import db, firebase_auth, get_user_profile # Import Firestore client, auth module, and helper
from google.cloud.firestore_v1.base_query import FieldFilter # For Firestore queries
from google.cloud.firestore import transactional # For atomic updates
import datetime
import logging

# Ensure Firebase was initialized
if not db or not firebase_auth:
    # Log a critical error if Firebase didn't initialize
    # This helps diagnose startup issues.
    logging.critical("Firestore DB or Firebase Auth is not available. Check firebase_config.py and initialization logs.")
    # You might want to prevent the app from starting fully,
    # but for now, views will check db/firebase_auth availability.

logger = logging.getLogger(__name__)

# --- Authentication Helper ---
def get_current_user_info(request):
    """
    Retrieves user info (UID, role, family ID) from the Django session.
    Returns (None, None, None) if the user is not logged in via session.
    """
    # **SECURITY NOTE:** This relies on the session being securely populated
    # ONLY after verifying a Firebase ID token (e.g., in the LoginView post-token verification).
    uid = request.session.get('user_uid')
    role = request.session.get('user_role')
    family_id = request.session.get('family_id')
    if not uid:
        return None, None, None # Not logged in according to session
    return uid, role, family_id

# --- Views ---

class SignUpView(View):
    """Handles user registration (creating Firebase Auth user and Firestore profile)."""
    def get(self, request):
        # If user is already logged in (e.g., via session), redirect them
        if request.session.get('user_uid'):
            return redirect('dashboard')
        return render(request, 'registration/signup.html')

    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')
        display_name = request.POST.get('display_name')
        role = request.POST.get('role') # 'parent' or 'child'
        family_name = request.POST.get('family_name', '').strip() # For new family by parent
        # Use family_id as the "code" for simplicity when joining
        family_code = request.POST.get('family_code', '').strip() # Family ID to join

        # Basic Validation
        if not all([email, password, display_name, role]):
             messages.error(request, "Please fill in all required fields (Email, Password, Display Name, Role).")
             return render(request, 'registration/signup.html', request.POST) # Pass POST data back

        if role not in ['parent', 'child']:
             messages.error(request, "Invalid role selected. Choose 'Parent' or 'Child'.")
             return render(request, 'registration/signup.html', request.POST)

        if role == 'parent' and not family_name and not family_code:
             messages.error(request, "Parent must either create a new family (provide Family Name) or join one (provide Family Code/ID).")
             return render(request, 'registration/signup.html', request.POST)

        if role == 'parent' and family_name and family_code:
             messages.error(request, "Please provide *either* a new Family Name *or* a Family Code/ID to join, not both.")
             return render(request, 'registration/signup.html', request.POST)

        if role == 'child' and not family_code:
             messages.error(request, "Child must provide a Family Code/ID to join.")
             return render(request, 'registration/signup.html', request.POST)

        # Check if Firebase services are available
        if not db or not firebase_auth:
             logger.critical("Sign up attempt failed: Firebase DB or Auth is not initialized.")
             messages.error(request, "Registration service is temporarily unavailable. Please try again later.")
             # Return a server error status code as this is a configuration issue
             return render(request, 'registration/signup.html', request.POST, status=503) # Service Unavailable

        user_record = None # Initialize to None
        try:
            # 1. Create Firebase Auth user
            user_record = firebase_auth.create_user(
                email=email,
                password=password,
                display_name=display_name
            )
            logger.info(f"Successfully created Firebase Auth user: {user_record.uid} for email: {email}")

            family_id_to_set = None
            family_ref = None

            # 2. Handle Family Creation / Joining
            if role == 'parent':
                if family_name: # Create new family
                    # Check if family name already exists (optional but recommended)
                    # Note: Firestore queries are case-sensitive. Consider storing a lower-case version for checks.
                    family_query = db.collection('families').where(filter=FieldFilter('family_name', '==', family_name)).limit(1).stream()
                    existing_families = list(family_query)
                    if len(existing_families) > 0:
                        messages.error(request, f"Family name '{family_name}' is already taken. Please choose another name.")
                        # Clean up the created auth user if family creation fails
                        firebase_auth.delete_user(user_record.uid)
                        logger.warning(f"Cleaned up auth user {user_record.uid} because family name '{family_name}' was taken.")
                        return render(request, 'registration/signup.html', request.POST)

                    # Create the new family document
                    family_ref = db.collection('families').document() # Auto-generate ID
                    family_ref.set({
                        'family_name': family_name,
                        'parent_uid': user_record.uid, # Link the first parent
                        'created_at': firestore.SERVER_TIMESTAMP
                        # Consider adding the family ID itself to the doc for easy retrieval if needed
                        # 'family_id': family_ref.id
                    })
                    family_id_to_set = family_ref.id
                    logger.info(f"Created new family '{family_name}' with ID: {family_id_to_set}")

                elif family_code: # Join existing family as a parent
                     # Assuming family_code is the actual document ID
                     family_ref = db.collection('families').document(family_code)
                     family_doc = family_ref.get()
                     if not family_doc.exists:
                         messages.error(request, "Invalid Family Code/ID provided.")
                         firebase_auth.delete_user(user_record.uid)
                         logger.warning(f"Cleaned up auth user {user_record.uid} due to invalid family code '{family_code}'.")
                         return render(request, 'registration/signup.html', request.POST)
                     family_id_to_set = family_doc.id
                     # Optionally add this parent's UID to the family doc if needed (e.g., for multi-parent families)
                     # family_ref.update({'additional_parents': firestore.ArrayUnion([user_record.uid])})
                     logger.info(f"Parent {user_record.uid} joining family ID: {family_id_to_set}")


            elif role == 'child':
                # Find family by code (which is the family_id)
                family_ref = db.collection('families').document(family_code)
                family_doc = family_ref.get()
                if not family_doc.exists:
                    messages.error(request, "Invalid Family Code/ID provided.")
                    firebase_auth.delete_user(user_record.uid) # Clean up auth user
                    logger.warning(f"Cleaned up auth user {user_record.uid} (child) due to invalid family code '{family_code}'.")
                    return render(request, 'registration/signup.html', request.POST)
                family_id_to_set = family_doc.id
                logger.info(f"Child {user_record.uid} joining family ID: {family_id_to_set}")


            # 3. Create user profile in Firestore
            if family_id_to_set:
                 user_profile_ref = db.collection('users').document(user_record.uid)
                 user_profile_ref.set({
                    'email': email, # Store email for reference, though auth is the source of truth
                    'display_name': display_name,
                    'role': role,
                    'family_id': family_id_to_set,
                    'total_points': 0, # Initialize points
                    'created_at': firestore.SERVER_TIMESTAMP
                 })
                 logger.info(f"Created Firestore user profile for UID: {user_record.uid} in family {family_id_to_set}")

                 # Log the user in immediately by setting up the Django session
                 # This assumes the signup implies immediate login.
                 request.session['user_uid'] = user_record.uid
                 request.session['user_role'] = role
                 request.session['family_id'] = family_id_to_set
                 request.session.set_expiry(1209600) # Set session expiry (e.g., 2 weeks)

                 messages.success(request, "Account created successfully! You are now logged in.")
                 return redirect('dashboard') # Redirect to the main dashboard

            else:
                 # This case should ideally not be reached if validation above is correct
                 messages.error(request, "Could not determine family association. Please check your input.")
                 firebase_auth.delete_user(user_record.uid) # Clean up auth user
                 logger.error(f"Signup failed for {user_record.uid}: family_id_to_set was None despite passing initial checks.")
                 return render(request, 'registration/signup.html', request.POST)


        except firebase_auth.EmailAlreadyExistsError:
            logger.warning(f"Sign up failed: Email '{email}' already exists.")
            messages.error(request, "An account with this email already exists. Please try logging in.")
            return render(request, 'registration/signup.html', request.POST)
        except firebase_auth.FirebaseAuthError as e:
            logger.error(f"Firebase Auth error during sign up for {email}: {e}", exc_info=True)
            messages.error(request, f"An error occurred during registration: {e}. Please try again.")
            # Don't delete user_record here as it might not have been created
            return render(request, 'registration/signup.html', request.POST)
        except Exception as e:
            logger.error(f"Unexpected error during sign up for {email}: {e}", exc_info=True)
            # Attempt to clean up created auth user if profile creation failed or other error occurred
            if user_record:
                try:
                    firebase_auth.delete_user(user_record.uid)
                    logger.info(f"Cleaned up Firebase Auth user {user_record.uid} due to signup error.")
                except Exception as delete_error:
                    logger.error(f"Failed to clean up Firebase Auth user {user_record.uid} after signup error: {delete_error}")
            messages.error(request, "An unexpected error occurred during registration. Please try again later.")
            return render(request, 'registration/signup.html', request.POST)


class LoginView(View):
    """Handles the display of the login form and processes the ID token verification."""

    def get(self, request):
        # If already logged in via session, redirect to dashboard
        if request.session.get('user_uid'):
            return redirect('dashboard')
        return render(request, 'registration/login.html')

    def post(self, request):
        # This view now expects an ID token submitted from the client-side Firebase login
        id_token = request.POST.get('id_token')

        if not id_token:
             messages.error(request, "Login process failed. ID token was not received.")
             # It's unusual to POST here without a token if client-side logic is correct.
             # Render login page again, maybe indicating a client-side script issue.
             logger.warning("Login POST request received without an ID token.")
             return render(request, 'registration/login.html', {'error': 'Login token missing.'})

        # Check if Firebase Auth service is available
        if not firebase_auth:
             logger.critical("Login attempt failed: Firebase Auth is not initialized.")
             messages.error(request, "Authentication service is temporarily unavailable. Please try again later.")
             return render(request, 'registration/login.html', {'error': 'Auth service unavailable.'}, status=503)

        try:
            # Verify the ID token using Firebase Admin SDK
            # This checks if the token is valid and not revoked.
            # It also decodes the token to get user information like UID.
            decoded_token = firebase_auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            logger.info(f"Successfully verified ID token for UID: {uid}")

            # Fetch the user's profile from Firestore to get role and family_id
            user_profile = get_user_profile(uid)
            if not user_profile:
                 # This indicates an inconsistency: Auth user exists, but Firestore profile doesn't.
                 # Could be due to an incomplete signup or data issue.
                 messages.error(request, "Login failed: User profile data not found. Please contact support.")
                 logger.error(f"Login failed for UID {uid}: Corresponding Firestore user profile not found.")
                 # Log the user out of Firebase on the client-side if possible?
                 # For now, just prevent Django session creation.
                 return render(request, 'registration/login.html', {'error': 'User profile incomplete.'})

            # --- Session Creation ---
            # Store essential, non-sensitive user info in the Django session
            request.session['user_uid'] = uid
            request.session['user_role'] = user_profile.get('role') # Get role from profile
            request.session['family_id'] = user_profile.get('family_id') # Get family ID
            request.session['display_name'] = user_profile.get('display_name') # Store display name for convenience
            request.session.set_expiry(1209600) # Set session expiry (e.g., 2 weeks)

            # Validate that essential session data was set
            if not request.session.get('user_role') or not request.session.get('family_id'):
                 messages.error(request, "Login failed: Could not retrieve essential user details (role or family). Please contact support.")
                 logger.error(f"Login failed for UID {uid}: Missing role or family_id in Firestore profile: {user_profile}")
                 # Clear potentially partially set session data
                 request.session.flush()
                 return render(request, 'registration/login.html', {'error': 'User data configuration error.'})

            logger.info(f"User {uid} ({request.session['display_name']}) logged in successfully. Role: {request.session['user_role']}, Family: {request.session['family_id']}")
            messages.success(request, "Login successful!")
            return redirect('dashboard') # Redirect to the main dashboard

        except firebase_auth.InvalidIdTokenError:
            logger.warning(f"Invalid ID token received during login attempt.")
            messages.error(request, "Login failed: Invalid or expired session token. Please try logging in again.")
            return render(request, 'registration/login.html', {'error': 'Invalid login token.'})
        except firebase_auth.ExpiredIdTokenError:
             logger.warning(f"Expired ID token received during login attempt.")
             messages.error(request, "Login failed: Your session token has expired. Please log in again.")
             return render(request, 'registration/login.html', {'error': 'Expired login token.'})
        except firebase_auth.RevokedIdTokenError:
             logger.warning(f"Revoked ID token received for UID: {decoded_token['uid'] if 'decoded_token' in locals() else 'unknown'}")
             messages.error(request, "Login failed: Your account session has been revoked. Please log in again.")
             return render(request, 'registration/login.html', {'error': 'Session revoked.'})
        except Exception as e:
            # Catch other potential errors during token verification or Firestore fetch
            logger.error(f"Error during login token verification or profile fetch: {e}", exc_info=True)
            messages.error(request, "An unexpected error occurred during login. Please try again later.")
            return render(request, 'registration/login.html', {'error': 'Login verification failed.'})


def logout_view(request):
    """Logs the user out by clearing the Django session."""
    # Client-side Firebase sign-out should also be triggered via JavaScript in the template
    # to ensure the Firebase Auth state is cleared.
    user_uid = request.session.get('user_uid')
    if user_uid:
        logger.info(f"Logging out user {user_uid} (clearing session).")
        request.session.flush() # Clears all data for the current session
        messages.success(request, "You have been successfully logged out.")
    else:
        messages.info(request, "You were not logged in.")
    return redirect('login') # Redirect to the login page


# --- Main Application Views ---

def dashboard(request):
    """Displays the appropriate dashboard based on user role stored in session."""
    user_uid, role, family_id = get_current_user_info(request)

    # Check if user is logged in (session data exists)
    if not user_uid:
        messages.warning(request, "Please log in to access the dashboard.")
        return redirect('login')

    # Check if Firebase DB is available
    if not db:
        logger.error(f"Dashboard access failed for user {user_uid}: Firestore DB not available.")
        messages.error(request, "The application database is temporarily unavailable. Please try again later.")
        # Render a simple error page or redirect appropriately
        return HttpResponseServerError("Database connection error.") # Or render an error template

    # Route to the correct dashboard based on role
    if role == 'parent':
        return parent_dashboard(request, user_uid, family_id)
    elif role == 'child':
        return child_dashboard(request, user_uid, family_id)
    else:
        # Handle cases where the role is missing or invalid in the session
        logger.error(f"User {user_uid} has invalid or missing role ('{role}') in session. Logging out.")
        messages.error(request, "Your user role is not configured correctly. Logging you out. Please contact support if this persists.")
        # Log the user out by clearing the potentially corrupted session
        request.session.flush()
        return redirect('login')


def parent_dashboard(request, user_uid, family_id):
    """Parent's view: Manage chores, view children's progress, assign chores."""
    if not family_id:
         # This shouldn't happen if login/signup sets the session correctly
         logger.error(f"Parent dashboard access failed for user {user_uid}: family_id missing in session.")
         messages.error(request, "Your family information is missing. Please try logging in again or contact support.")
         request.session.flush() # Clear potentially bad session
         return redirect('login')

    try:
        # 1. Get family members (children only)
        children_query = db.collection('users') \
            .where(filter=FieldFilter('family_id', '==', family_id)) \
            .where(filter=FieldFilter('role', '==', 'child')) \
            .order_by('display_name') \
            .stream()
        children = [{'id': doc.id, **doc.to_dict()} for doc in children_query]

        # 2. Get active chores defined for the family
        chores_query = db.collection('chores') \
            .where(filter=FieldFilter('family_id', '==', family_id)) \
            .where(filter=FieldFilter('is_active', '==', True)) \
            .order_by('name') \
            .stream()
        active_chores = [{'id': doc.id, **doc.to_dict()} for doc in chores_query]

        # 3. Get assigned chores needing action (pending or completed/needs verification)
        assignments_query = db.collection('assigned_chores') \
            .where(filter=FieldFilter('family_id', '==', family_id)) \
            .where(filter=FieldFilter('status', 'in', ['completed', 'pending'])) \
            .order_by('assigned_date', direction='DESC') \
            .stream() # Order by most recently assigned

        assignments_list = []
        # Use dictionaries to cache chore names and child names to reduce Firestore reads
        chore_names = {chore['id']: chore['name'] for chore in active_chores}
        child_names = {child['id']: child['display_name'] for child in children}

        for doc in assignments_query:
            assignment = {'id': doc.id, **doc.to_dict()}
            chore_id = assignment.get('chore_id')
            child_uid = assignment.get('user_uid')

            # Get chore name (use cache, fallback to DB read if not active/found)
            if chore_id in chore_names:
                assignment['chore_name'] = chore_names[chore_id]
            else:
                chore_doc = db.collection('chores').document(chore_id).get(('name',)) # Fetch only name
                assignment['chore_name'] = chore_doc.get('name') if chore_doc.exists else 'Deleted Chore'
                if chore_doc.exists: chore_names[chore_id] = assignment['chore_name'] # Cache if found

            # Get child name (use cache, fallback to DB read if needed)
            if child_uid in child_names:
                 assignment['child_name'] = child_names[child_uid]
            else:
                 user_doc = db.collection('users').document(child_uid).get(('display_name',)) # Fetch only name
                 assignment['child_name'] = user_doc.get('display_name') if user_doc.exists else 'Unknown Child'
                 if user_doc.exists: child_names[child_uid] = assignment['child_name'] # Cache if found

            assignments_list.append(assignment)


        context = {
            'children': children,
            'active_chores': active_chores,
            'assignments': assignments_list,
            'family_id': family_id, # Pass family ID for display/use in forms
            'display_name': request.session.get('display_name', 'Parent') # Get display name from session
        }
        return render(request, 'chores/parent_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error loading parent dashboard for user {user_uid}, family {family_id}: {e}", exc_info=True)
        messages.error(request, "Could not load dashboard data due to a server error.")
        # Render the template with an error message, but without sensitive data if possible
        return render(request, 'chores/parent_dashboard.html', {'error': 'Failed to load dashboard data.'})


def child_dashboard(request, user_uid, family_id):
    """Child's view: View assigned chores, mark complete, see leaderboard."""
    if not family_id:
         # Should not happen if session is set correctly
         logger.error(f"Child dashboard access failed for user {user_uid}: family_id missing in session.")
         messages.error(request, "Your family information is missing. Please try logging in again or contact support.")
         request.session.flush()
         return redirect('login')

    try:
        # 1. Get the child's current profile (needed for points display)
        user_profile = get_user_profile(user_uid)
        if not user_profile:
             # If the profile is missing, something is wrong. Log out.
             logger.error(f"Child dashboard failed for UID {user_uid}: Firestore user profile not found.")
             messages.error(request, "Could not load your profile data. Logging out.")
             request.session.flush()
             return redirect('login')

        # 2. Get child's currently pending assigned chores
        assigned_chores_query = db.collection('assigned_chores') \
            .where(filter=FieldFilter('user_uid', '==', user_uid)) \
            .where(filter=FieldFilter('status', '==', 'pending')) \
            .order_by('assigned_date') \
            .stream()

        pending_chores = []
        chore_details_cache = {} # Cache chore details to reduce reads

        for doc in assigned_chores_query:
            assignment = {'id': doc.id, **doc.to_dict()}
            chore_id = assignment.get('chore_id')

            # Fetch chore details (use cache or query)
            if chore_id in chore_details_cache:
                assignment['chore_details'] = chore_details_cache[chore_id]
            elif chore_id:
                chore_doc = db.collection('chores').document(chore_id).get()
                if chore_doc.exists:
                    chore_data = chore_doc.to_dict()
                    assignment['chore_details'] = chore_data
                    chore_details_cache[chore_id] = chore_data # Cache it
                else:
                     assignment['chore_details'] = {'name': 'Deleted Chore', 'points': 0, 'description': ''}
                     logger.warning(f"Chore document {chore_id} not found for assignment {assignment['id']}")
            else:
                 assignment['chore_details'] = {'name': 'Invalid Chore ID', 'points': 0, 'description': ''}
                 logger.error(f"Assignment {assignment['id']} has missing chore_id.")

            pending_chores.append(assignment)

        # 3. Get family leaderboard (children only, sorted by total_points)
        leaderboard_query = db.collection('users') \
            .where(filter=FieldFilter('family_id', '==', family_id)) \
            .where(filter=FieldFilter('role', '==', 'child')) \
            .order_by('total_points', direction='DESC') \
            .limit(10) \
            .stream() # Limit leaderboard size if necessary
        leaderboard = [{'id': doc.id, **doc.to_dict()} for doc in leaderboard_query]

        context = {
            'user_profile': user_profile, # Contains display_name, total_points etc.
            'pending_chores': pending_chores,
            'leaderboard': leaderboard,
            'display_name': user_profile.get('display_name', 'Child') # Use profile display name
        }
        return render(request, 'chores/child_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error loading child dashboard for user {user_uid}, family {family_id}: {e}", exc_info=True)
        messages.error(request, "Could not load your dashboard data due to a server error.")
        return render(request, 'chores/child_dashboard.html', {'error': 'Failed to load dashboard data.'})


# --- Action Views (typically called via POST from forms) ---

def add_chore(request):
    """Adds a new chore definition (Parent action only)."""
    user_uid, role, family_id = get_current_user_info(request)

    # Security and Permission Check
    if not user_uid or role != 'parent' or not family_id:
        messages.error(request, "You do not have permission to add chores.")
        logger.warning(f"Unauthorized attempt to add chore by user {user_uid} (role: {role}).")
        return redirect('dashboard') # Redirect non-parents or unauthenticated users

    if not db:
         messages.error(request, "Database service unavailable.")
         return redirect('dashboard')

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        points_str = request.POST.get('points')

        # Validation
        if not name or not points_str:
            messages.error(request, "Chore name and points value are required.")
            # Redirect back, potentially preserving form data if using Django forms
            return redirect('dashboard')

        try:
            points = int(points_str)
            if points <= 0:
                 messages.error(request, "Points must be a positive number.")
                 return redirect('dashboard')

            # Add chore to Firestore
            new_chore_ref = db.collection('chores').document()
            new_chore_ref.set({
                'family_id': family_id, # Associate with the parent's family
                'name': name,
                'description': description,
                'points': points,
                'is_active': True, # Chores are active by default
                'created_at': firestore.SERVER_TIMESTAMP,
                'created_by': user_uid # Optional: track who created it
            })
            logger.info(f"Parent {user_uid} added chore '{name}' ({points} points) for family {family_id}")
            messages.success(request, f"Chore '{name}' added successfully.")

        except ValueError:
             messages.error(request, "Invalid points value. Please enter a whole number.")
        except Exception as e:
            logger.error(f"Error adding chore for family {family_id} by user {user_uid}: {e}", exc_info=True)
            messages.error(request, "An unexpected error occurred while adding the chore.")

        return redirect('dashboard') # Redirect back to parent dashboard
    else:
        # If accessed via GET, just redirect
        return redirect('dashboard')


def assign_chore(request):
    """Assigns an existing active chore to a child (Parent action only)."""
    user_uid, role, family_id = get_current_user_info(request)

    # Security and Permission Check
    if not user_uid or role != 'parent' or not family_id:
        messages.error(request, "You do not have permission to assign chores.")
        logger.warning(f"Unauthorized attempt to assign chore by user {user_uid} (role: {role}).")
        return redirect('dashboard')

    if not db:
         messages.error(request, "Database service unavailable.")
         return redirect('dashboard')

    if request.method == 'POST':
        chore_id = request.POST.get('chore_id')
        child_uid = request.POST.get('child_uid')
        # due_date_str = request.POST.get('due_date') # Optional: Add date parsing if needed

        # Validation
        if not chore_id or not child_uid:
            messages.error(request, "You must select both a chore and a child to assign.")
            return redirect('dashboard')

        try:
            # --- Verification ---
            # 1. Verify the selected chore exists, is active, and belongs to the parent's family.
            chore_ref = db.collection('chores').document(chore_id)
            chore_doc = chore_ref.get()
            if not chore_doc.exists:
                 messages.error(request, "The selected chore does not exist.")
                 return redirect('dashboard')

            chore_data = chore_doc.to_dict()
            if chore_data.get('family_id') != family_id:
                 messages.error(request, "Cannot assign a chore from another family.")
                 logger.warning(f"Security Violation: Parent {user_uid} (family {family_id}) attempted to assign chore {chore_id} from family {chore_data.get('family_id')}.")
                 return redirect('dashboard')
            if not chore_data.get('is_active', False):
                 messages.error(request, f"Chore '{chore_data.get('name')}' is not currently active.")
                 return redirect('dashboard')

            # 2. Verify the selected child exists, is a child, and belongs to the parent's family.
            child_ref = db.collection('users').document(child_uid)
            child_doc = child_ref.get()
            if not child_doc.exists:
                messages.error(request, "The selected child does not exist.")
                return redirect('dashboard')

            child_data = child_doc.to_dict()
            if child_data.get('family_id') != family_id:
                 messages.error(request, "Cannot assign a chore to a child from another family.")
                 logger.warning(f"Security Violation: Parent {user_uid} (family {family_id}) attempted to assign chore to child {child_uid} from family {child_data.get('family_id')}.")
                 return redirect('dashboard')
            if child_data.get('role') != 'child':
                 messages.error(request, "Chores can only be assigned to users with the 'child' role.")
                 return redirect('dashboard')

            # --- Create Assignment ---
            # Store the points value *at the time of assignment* in case the chore definition changes later.
            points_at_assignment = chore_data.get('points', 0)

            new_assignment_ref = db.collection('assigned_chores').document()
            new_assignment_ref.set({
                'chore_id': chore_id,
                'user_uid': child_uid, # The child it's assigned to
                'family_id': family_id,
                'assigned_by': user_uid, # Track which parent assigned it
                'assigned_date': firestore.SERVER_TIMESTAMP,
                'due_date': None, # Add logic to parse due_date_str if using date field
                'status': 'pending', # Initial status
                'completed_date': None,
                'verified_date': None,
                'points_awarded': points_at_assignment # Store points from chore definition
            })
            logger.info(f"Parent {user_uid} assigned chore {chore_id} ('{chore_data.get('name')}') to child {child_uid} ({child_data.get('display_name')}) in family {family_id}")
            messages.success(request, f"Chore '{chore_data.get('name')}' assigned to {child_data.get('display_name')}.")

        except Exception as e:
            logger.error(f"Error assigning chore {chore_id} to child {child_uid} by parent {user_uid}: {e}", exc_info=True)
            messages.error(request, "An unexpected error occurred while assigning the chore.")

        return redirect('dashboard')
    else:
        # If accessed via GET, just redirect
        return redirect('dashboard')


def complete_chore(request, assignment_id):
    """Marks a chore assignment as completed by the child who owns it."""
    user_uid, role, family_id = get_current_user_info(request)

    # Security and Permission Check
    if not user_uid or role != 'child' or not family_id:
        messages.error(request, "Only children can mark their own chores as completed.")
        logger.warning(f"Unauthorized attempt to complete chore {assignment_id} by user {user_uid} (role: {role}).")
        # Use status 403 for forbidden access if it's an API-like endpoint, or redirect for web flow
        return redirect('dashboard') # Or return HttpResponseForbidden()

    if not db:
         messages.error(request, "Database service unavailable.")
         return redirect('dashboard')

    if request.method == 'POST':
        try:
            assignment_ref = db.collection('assigned_chores').document(assignment_id)
            assignment_doc = assignment_ref.get()

            if not assignment_doc.exists:
                messages.error(request, "This chore assignment was not found.")
                logger.warning(f"Child {user_uid} tried to complete non-existent assignment {assignment_id}.")
                raise Http404 # Raise 404 to prevent further processing

            assignment_data = assignment_doc.to_dict()

            # --- Verification ---
            # 1. Ensure the chore belongs to the logged-in child.
            if assignment_data.get('user_uid') != user_uid:
                messages.error(request, "You can only complete chores assigned to you.")
                logger.warning(f"Security Violation: Child {user_uid} attempted to complete chore {assignment_id} belonging to {assignment_data.get('user_uid')}.")
                return redirect('dashboard') # Or HttpResponseForbidden()

            # 2. Ensure the chore is currently in 'pending' status.
            if assignment_data.get('status') != 'pending':
                 messages.warning(request, f"This chore is already marked as '{assignment_data.get('status')}'.")
                 return redirect('dashboard')

            # --- Update Assignment Status ---
            # Decide if completion immediately awards points OR requires parent verification first.
            # Option A: Mark as 'completed' (needs verification)
            # Option B: Mark as 'verified' (skip verification, award points now)

            # Let's implement Option A: Mark as 'completed', points awarded upon verification.
            update_data = {
                'status': 'completed',
                'completed_date': firestore.SERVER_TIMESTAMP
            }
            assignment_ref.update(update_data)
            logger.info(f"Child {user_uid} marked chore assignment {assignment_id} as 'completed'. Awaiting verification.")
            messages.success(request, "Chore marked as done! Your parent will verify it.")

            # --- Point Awarding (If NOT waiting for verification - Option B logic) ---
            # If you wanted points awarded immediately:
            # points_to_award = assignment_data.get('points_awarded', 0)
            # if points_to_award > 0:
            #     user_ref = db.collection('users').document(user_uid)
            #     try:
            #         # Use Firestore transaction for atomic update
            #         @transactional
            #         def update_points(transaction, user_ref, points):
            #             snapshot = user_ref.get(transaction=transaction, field_paths={'total_points'}) # Fetch only points
            #             current_points = snapshot.get('total_points') or 0
            #             new_total = current_points + points
            #             transaction.update(user_ref, {'total_points': new_total})
            #             logger.info(f"Transactionally updated points for {user_uid}. New total: {new_total}")
            #             return new_total # Return new total for logging/confirmation

            #         transaction = db.transaction() # Start a transaction
            #         new_total_points = update_points(transaction, user_ref, points_to_award)

            #         # Update status to 'verified' if points awarded immediately
            #         update_data['status'] = 'verified'
            #         assignment_ref.update(update_data) # Update status within the same flow

            #         logger.info(f"Child {user_uid} completed chore {assignment_id}. Awarded {points_to_award} points. New total: {new_total_points}.")
            #         messages.success(request, f"Chore marked as complete! You earned {points_to_award} points.")

            #     except Exception as tx_error:
            #         logger.error(f"Transaction failed updating points for user {user_uid} after completing chore {assignment_id}: {tx_error}", exc_info=True)
            #         messages.error(request, "Could not update your points due to a database error. Chore marked complete, please notify parent.")
            #         # Chore status might still be 'pending' if transaction failed before status update
            #         # Consider how to handle this inconsistency. Maybe revert status update?
            # else:
            #      # Chore completed, but no points associated or awarded yet
            #      assignment_ref.update(update_data) # Just update status
            #      logger.info(f"Child {user_uid} completed chore {assignment_id} (status set to 'verified', 0 points).")
            #      messages.success(request, "Chore marked as complete.")


        except Http404:
             # Message already set above
             return redirect('dashboard') # Redirect on 404
        except Exception as e:
            logger.error(f"Error completing chore {assignment_id} for user {user_uid}: {e}", exc_info=True)
            messages.error(request, "An unexpected error occurred while marking the chore as complete.")

        return redirect('dashboard') # Redirect back to child dashboard
    else:
        # If accessed via GET, just redirect
        return redirect('dashboard')


def verify_chore(request, assignment_id):
    """Verifies a 'completed' chore (Parent action) and awards points."""
    user_uid, role, family_id = get_current_user_info(request)

    # Security and Permission Check
    if not user_uid or role != 'parent' or not family_id:
        messages.error(request, "You do not have permission to verify chores.")
        logger.warning(f"Unauthorized attempt to verify chore {assignment_id} by user {user_uid} (role: {role}).")
        return redirect('dashboard') # Or HttpResponseForbidden()

    if not db:
         messages.error(request, "Database service unavailable.")
         return redirect('dashboard')

    if request.method == 'POST':
        try:
            assignment_ref = db.collection('assigned_chores').document(assignment_id)

            # Use a transaction to ensure atomicity of checking status, updating status, and awarding points
            @transactional
            def verify_and_award_points(transaction, assignment_ref):
                assignment_doc = assignment_ref.get(transaction=transaction)

                if not assignment_doc.exists:
                    logger.warning(f"Parent {user_uid} tried to verify non-existent assignment {assignment_id}.")
                    # Cannot set message inside transaction, handle return value
                    return "not_found", None, 0

                assignment_data = assignment_doc.to_dict()
                child_uid = assignment_data.get('user_uid')
                points_to_award = assignment_data.get('points_awarded', 0)

                # --- Verification within Transaction ---
                # 1. Ensure the chore belongs to the parent's family.
                if assignment_data.get('family_id') != family_id:
                    logger.warning(f"Security Violation: Parent {user_uid} (family {family_id}) attempted to verify chore {assignment_id} from family {assignment_data.get('family_id')}.")
                    return "forbidden_family", None, 0

                # 2. Ensure the chore is in 'completed' status.
                if assignment_data.get('status') != 'completed':
                    logger.warning(f"Parent {user_uid} attempted to verify chore {assignment_id} which has status '{assignment_data.get('status')}'.")
                    return "wrong_status", assignment_data.get('status'), 0

                # --- Actions within Transaction ---
                # 1. Update assignment status to 'verified'
                update_data = {
                    'status': 'verified',
                    'verified_date': firestore.SERVER_TIMESTAMP,
                    'verified_by': user_uid # Track who verified
                }
                transaction.update(assignment_ref, update_data)

                # 2. Award points to the child if points > 0
                if points_to_award > 0 and child_uid:
                    user_ref = db.collection('users').document(child_uid)
                    user_snapshot = user_ref.get(transaction=transaction, field_paths={'total_points'})
                    current_points = user_snapshot.get('total_points') or 0
                    new_total = current_points + points_to_award
                    transaction.update(user_ref, {'total_points': new_total})
                    logger.info(f"Transactionally awarded {points_to_award} points to child {child_uid} for chore {assignment_id}. New total: {new_total}")
                    return "success", child_uid, points_to_award
                else:
                    # Chore verified, but no points awarded (or child_uid missing)
                    logger.info(f"Parent {user_uid} verified chore {assignment_id}. No points awarded ({points_to_award} points, child: {child_uid}).")
                    return "success_no_points", child_uid, 0

            # Execute the transaction
            transaction = db.transaction()
            result_status, awarded_to_child, points_value = verify_and_award_points(transaction, assignment_ref)

            # Handle results outside the transaction
            if result_status == "success":
                 messages.success(request, f"Chore verified successfully! {points_value} points awarded.")
            elif result_status == "success_no_points":
                 messages.success(request, "Chore verified successfully (0 points awarded).")
            elif result_status == "not_found":
                 messages.error(request, "Chore assignment not found.")
            elif result_status == "forbidden_family":
                 messages.error(request, "Cannot verify chores outside your family.")
            elif result_status == "wrong_status":
                 messages.warning(request, f"This chore is not awaiting verification (current status: '{awarded_to_child}').") # Reusing variable here
            else:
                 # General transaction failure
                 messages.error(request, "Failed to verify chore due to a database conflict or error. Please try again.")


        except Exception as e:
            logger.error(f"Error verifying chore {assignment_id} by parent {user_uid}: {e}", exc_info=True)
            messages.error(request, "An unexpected error occurred while verifying the chore.")

        return redirect('dashboard') # Redirect back to parent dashboard
    else:
        # If accessed via GET, just redirect
        return redirect('dashboard')


# --- Reward System View (Informational) ---
def check_rewards(request):
    """
    (Parent Only) Displays children who have met a point threshold.
    Does NOT automate gift card purchase/emailing.
    """
    user_uid, role, family_id = get_current_user_info(request)

    # Security and Permission Check
    if not user_uid or role != 'parent' or not family_id:
        messages.error(request, "You do not have permission to view reward eligibility.")
        return redirect('dashboard') # Or HttpResponseForbidden()

    if not db:
         messages.error(request, "Database service unavailable.")
         return redirect('dashboard')

    # Define reward threshold (Consider making this configurable per family in Firestore)
    REWARD_THRESHOLD = 500 # Example: 500 points

    try:
        # Query for children in the family who meet or exceed the threshold
        eligible_children_query = db.collection('users') \
            .where(filter=FieldFilter('family_id', '==', family_id)) \
            .where(filter=FieldFilter('role', '==', 'child')) \
            .where(filter=FieldFilter('total_points', '>=', REWARD_THRESHOLD)) \
            .order_by('total_points', direction='DESC') \
            .stream()

        eligible_children = [{'id': doc.id, **doc.to_dict()} for doc in eligible_children_query]

        # **IMPORTANT**: Replace with your actual affiliate link structure.
        # This is just a placeholder. You'll need to get this from giftcards.com
        # or your affiliate program provider. It might involve adding parameters.
        affiliate_link_template = "https://your_affiliate_link.giftcards.com/?tag=yourtag&utm_source=yourapp"

        context = {
            'eligible_children': eligible_children,
            'reward_threshold': REWARD_THRESHOLD,
            'affiliate_link': affiliate_link_template, # Provide the base link/template
            'display_name': request.session.get('display_name', 'Parent')
        }

        # This view simply PRESENTS the information and the link.
        # The parent must manually:
        # 1. Click the link.
        # 2. Purchase the gift card on the external site.
        # 3. Handle emailing/delivery.
        # 4. (Optional Future Feature) Return to the app to "claim" the reward,
        #    which might deduct points or log the reward event in Firestore.
        return render(request, 'chores/rewards.html', context)

    except Exception as e:
        logger.error(f"Error checking rewards for family {family_id} by parent {user_uid}: {e}", exc_info=True)
        messages.error(request, "Could not load reward eligibility information due to a server error.")
        # Redirect back to dashboard on error
        return redirect('dashboard')


