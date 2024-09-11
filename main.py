# main.py
import time
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import User, Withdrawals, UnidentifiedDeposits, ReportingData
import pandas as pd
from pivottablejs import pivot_ui
from config import Config
from werkzeug.security import generate_password_hash
from datetime import datetime
import logging

# Setting up the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Set the secret key for the Flask app from the configuration
app.secret_key = Config.SECRET_KEY
logger.info("Flask app initialized with secret key.")

# Initialize LoginManager with Flask app instance for handling user sessions
login_manager = LoginManager(app)
logger.info("LoginManager initialized with Flask app instance.")



# main.py

@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user by their user ID.

    This function is used by Flask-Login to reload the user object from the user ID stored in the session.

    Args:
        user_id (int): The ID of the user.

    Returns:
        User: The user object if found, otherwise None.
    """
    try:
        user_id_int = int(user_id)
        logger.info(f"Attempting to load user with ID: {user_id_int}")
        user = User.get_by_id(user_id_int)
        if user:
            logger.info(f"User {user_id_int} loaded successfully.")
        else:
            logger.warning(f"User {user_id_int} not found.")
        return user
    except ValueError as e:
        logger.error(f"Invalid user ID: {user_id}. Error: {e}")
        return None
    except Exception as e:
        logger.error(f"An error occurred while loading user with ID: {user_id}. Error: {e}")
        return None


@app.route('/')
def index():
    """
    Handles requests to the root URL ('/') of the application.

    This function renders the login page template (`login.html`). This is typically the page shown to users
    when they first access the application or when they need to log in.

    Returns:
        str: The rendered HTML template for the login page.
    """
    try:
        logger.info("Rendering the login page.")
        return render_template('login.html')
    except Exception as e:
        logger.error(f"An error occurred while rendering the login page: {e}")
        return "An error occurred while processing your request.", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login requests.

    Supports both GET and POST methods:
    - GET: Renders the login page.
    - POST: Processes login credentials and logs the user in if credentials are valid.

    Returns:
        str: Rendered HTML template for the login page or redirect URL to dashboard.
    """
    if request.method == 'POST':
        try:
            # Retrieve form data
            username = request.form.get('username')
            password = request.form.get('password')

            # Log the attempt to login
            logger.info(f"Login attempt for username: {username}")

            # Use the User model method to get user by username
            user = User.get_by_username(username)
            if user:
                logger.info(f"User found: {username}")

                # Check password and log in the user if valid
                if user.check_password(password):
                    login_user(user)
                    if current_user.is_authenticated:
                        logger.info(f"User {username} is authenticated.")
                    return redirect(url_for('dashboard'))  # Redirect to dashboard upon successful login
                else:
                    logger.warning(f"Invalid password for user: {username}")
            else:
                logger.warning(f"User not found: {username}")
            
            # Render login page with error message if login fails
            return render_template('login.html', error="Invalid username or password.")
        
        except Exception as e:
            logger.error(f"An error occurred during login: {e}")
            return render_template('login.html', error="An error occurred. Please try again.")
    
    # Render login page if method is GET
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """
    Logs out the currently authenticated user and redirects them to the login page.

    Requires the user to be logged in to access this route.

    Returns:
        Response: A redirect response to the login page.
    """
    try:
        # Log the logout action
        logger.info(f"User {current_user.username} logging out.")

        # Log out the user
        logout_user()

        # Redirect to the login page
        return redirect(url_for('login'))
    
    except Exception as e:
        logger.error(f"An error occurred during logout: {e}")
        # Optionally, render an error page or redirect to an error page
        return "An error occurred during logout. Please try again.", 500


def hash_password(password):
    """
    Hashes a password using Werkzeug's generate_password_hash function.

    This function takes a plain-text password and returns its hashed version
    using a secure hashing algorithm. The hashed password can be stored in
    a database for secure authentication.

    Args:
        password (str): The plain-text password to be hashed.

    Returns:
        str: The hashed password.

    Raises:
        ValueError: If the password is None or empty.
    """
    if not password:
        logger.error("Password cannot be None or empty.")
        raise ValueError("Password cannot be None or empty.")
    
    # Log the hashing action
    logger.info("Hashing the password.")

    try:
        hashed_password = generate_password_hash(password)
        logger.info("Password hashed successfully.")
        return hashed_password
    except Exception as e:
        logger.error(f"An error occurred while hashing the password: {e}")
        raise


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    """
    Handles the creation of a new user.

    Supports both GET and POST methods:
    - GET: Renders the user creation page.
    - POST: Processes form submission to create a new user with a hashed password.

    Requires the user to be logged in to access this route.

    Returns:
        Response: A redirect response to the dashboard upon successful user creation
                  or a rendered template for user creation.
    """
    if request.method == 'POST':
        try:
            # Retrieve form data
            username = request.form.get('username')
            password = request.form.get('password')

            # Log the attempt to create a user
            logger.info(f"Attempting to create user with username: {username}")

            # Validate input
            if not username or not password:
                logger.warning("Username and password are required.")
                return render_template('create_user.html', error="Username and password are required.")

            # Hash the password before storing it
            password_hash = hash_password(password)
            
            # Create the user in the database
            User.create_user(username, password_hash)
            logger.info(f"User {username} created successfully.")

            # Redirect to the dashboard upon successful user creation
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"An error occurred while creating the user: {e}")
            return render_template('create_user.html', error="An error occurred while creating the user. Please try again.")
    
    # Handle GET requests by rendering the user creation page
    return render_template('create_user.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page for authenticated users.

    This route is protected by the `login_required` decorator, meaning only logged-in users can access it.

    Returns:
        Response: Rendered HTML template for the dashboard page.
    """
    try:
        # Log the access to the dashboard
        logger.info(f"User {current_user.username} accessed the dashboard.")
        
        # Render the dashboard page
        return render_template('dashboard.html')
    
    except Exception as e:
        # Log any errors that occur during rendering
        logger.error(f"An error occurred while rendering the dashboard: {e}")
        
        # Optionally, render an error page or redirect to an error page
        return "An error occurred while processing your request.", 500
    

@app.route('/api/request_withdrawal', methods=['POST'])
def create_withdrawal_request():
    """
    Handles the creation of a withdrawal request via a POST request.

    This endpoint processes withdrawal requests by extracting data from the JSON payload,
    and then calling a stored procedure to save the data to the database.

    Returns:
        Response: A JSON response with a success message or an error message.
    """
    if request.method == 'POST':
        try:
            # Extract JSON data from the request
            data = request.json

            # Log the receipt of the withdrawal request
            logger.info("Received withdrawal request data: %s", data)

            # Extract data from JSON payload
            chat_id = data.get('chat_id')
            firstname = data.get('firstname')
            lastname = data.get('lastname')
            currency = data.get('currency')
            amount = data.get('amount')
            wallet = data.get('wallet')

            # Validate extracted data
            if not all([chat_id, firstname, lastname, currency, amount, wallet]):
                logger.warning("Missing required fields in withdrawal request data.")
                return jsonify({
                    'message': 'Missing required fields in request'
                }), 400

            # Log the extracted data for debugging
            logger.info("Creating withdrawal request with chat_id: %s, firstname: %s, lastname: %s, currency: %s, amount: %s, wallet: %s",
                        chat_id, firstname, lastname, currency, amount, wallet)

            # Call the database procedure to create a withdrawal request
            Withdrawals.create_withdrawal_request(chat_id, firstname, lastname, currency, amount, wallet)

            # Return a success response
            return jsonify({
                'message': 'Withdrawal request processed successfully'
            }), 200

        except Exception as e:
            # Log any errors that occur during processing
            logger.error(f"An error occurred while processing the withdrawal request: {e}")

            # Return an error response
            return jsonify({
                'message': 'An error occurred while processing the request'
            }), 500
            

@app.route('/api/client_withdrawal_page_update', methods=['POST'])
@login_required
def client_withdrawals_page_update():
    """
    Retrieves and returns all withdrawal requests in JSON format.

    This endpoint handles POST requests to fetch all withdrawal requests from the database.
    The data is then converted to a list of dictionaries and returned as a JSON response.

    Returns:
        Response: A JSON response containing a list of all withdrawal requests.
    """
    try:
        # Retrieve all withdrawal requests from the database
        withdrawals = Withdrawals.get_all_withdrawal_requests()

        # Convert the retrieved data to a list of dictionaries
        withdrawals_data = [dict(row) for row in withdrawals]
        
        # Log the retrieved data for debugging purposes
        logger.info("Retrieved withdrawal requests data: %s", withdrawals_data)
        
        # Return the data as a JSON response
        return jsonify(withdrawals_data)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or conversion
        logger.error(f"An error occurred while retrieving withdrawal requests: {e}")
        
        # Return an error response
        return jsonify({
            'message': 'An error occurred while retrieving the data'
        }), 500


@app.route('/api/approved_withdrawals_page_update', methods=['POST'])
@login_required
def approved_withdrawals_page_update():
    """
    Retrieves and returns all approved withdrawal requests in JSON format.

    This endpoint handles POST requests to fetch all approved withdrawal requests from the database.
    The data is then converted to a list of dictionaries and returned as a JSON response.

    Returns:
        Response: A JSON response containing a list of all approved withdrawal requests.
    """
    try:
        # Retrieve all approved withdrawal requests from the database
        withdrawals = Withdrawals.get_all_approved_withdrawals()

        # Convert the retrieved data to a list of dictionaries
        withdrawals_data = [dict(row) for row in withdrawals]
        
        # Log the retrieved data for debugging purposes
        logger.info("Retrieved approved withdrawal requests data: %s", withdrawals_data)
        
        # Return the data as a JSON response
        return jsonify(withdrawals_data)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or conversion
        logger.error(f"An error occurred while retrieving approved withdrawals: {e}")
        
        # Return an error response
        return jsonify({
            'message': 'An error occurred while retrieving the data'
        }), 500


@app.route('/api/declined_withdrawals_page_update', methods=['POST'])
@login_required
def declined_withdrawals_page_update():
    """
    Retrieves and returns all declined withdrawal requests in JSON format.

    This endpoint handles POST requests to fetch all declined withdrawal requests from the database.
    The data is then converted to a list of dictionaries and returned as a JSON response.

    Returns:
        Response: A JSON response containing a list of all declined withdrawal requests.
    """
    try:
        # Retrieve all declined withdrawal requests from the database
        withdrawals = Withdrawals.get_all_declined_withdrawals()

        # Convert the retrieved data to a list of dictionaries
        withdrawals_data = [dict(row) for row in withdrawals]
        
        # Log the retrieved data for debugging purposes
        logger.info("Retrieved declined withdrawal requests data: %s", withdrawals_data)
        
        # Return the data as a JSON response
        return jsonify(withdrawals_data)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or conversion
        logger.error(f"An error occurred while retrieving declined withdrawals: {e}")
        
        # Return an error response
        return jsonify({
            'message': 'An error occurred while retrieving the data'
        }), 500


@app.route('/api/lock_record', methods=['POST'])
def lock_record():
    """
    Locks a withdrawal record by updating its status in the database.

    This endpoint handles POST requests to lock a specific withdrawal record. It requires
    both 'wrid' (withdrawal record ID) and 'admin_id' to be provided in the JSON payload.

    Returns:
        Response: A JSON response indicating success or an error message.
    """
    try:
        # Extract JSON data from the request
        data = request.json
        
        # Retrieve 'wrid' and 'admin_id' from the JSON payload
        wrid = data.get('wrid')
        admin_id = data.get('admin_id')

        # Validate the required fields
        if not wrid or not admin_id:
            logger.warning("Validation failed: 'wrid' and 'admin_id' are required.")
            return jsonify({'error': 'Both wrid and admin_id are required'}), 400

        # Log the attempt to lock the record
        logger.info(f"Attempting to lock record with wrid: {wrid} by admin_id: {admin_id}")

        # Call the method to lock the withdrawal record
        Withdrawals.lock_withdrawal_record(wrid, admin_id)
        
        # Return a success response
        return jsonify({'message': 'Record locked successfully'}), 200

    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"An error occurred while locking the record: {e}")
        
        # Return an error response
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/unlock_record', methods=['POST'])
def unlock_record():
    """
    Unlocks a withdrawal record by updating its status in the database.

    This endpoint handles POST requests to unlock a specific withdrawal record.
    It requires 'wrid' (withdrawal record ID) to be provided in the JSON payload.

    Returns:
        Response: A JSON response indicating success or an error message.
    """
    try:
        # Extract JSON data from the request
        data = request.json
        
        # Retrieve 'wrid' from the JSON payload
        wrid = data.get('wrid')

        # Validate the required field
        if not wrid:
            logger.warning("Validation failed: 'wrid' is required.")
            return jsonify({'error': 'wrid is required'}), 400

        # Log the attempt to unlock the record
        logger.info(f"Attempting to unlock record with wrid: {wrid}")

        # Call the method to unlock the withdrawal record
        Withdrawals.unlock_withdrawal_record(wrid)
        
        # Return a success response
        return jsonify({'message': 'Record unlocked successfully'}), 200

    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"An error occurred while unlocking the record: {e}")
        
        # Return an error response
        return jsonify({'error': 'An error occurred while processing the request'}), 500
 

@app.route('/api/withdrawal_to_approved', methods=['POST'])
def withdrawal_to_approved():
    """
    Approves a withdrawal request and notifies the client application.

    This endpoint handles POST requests to approve a specific withdrawal request.
    It requires 'wrid' (withdrawal record ID) and 'admin_id' to be provided in the JSON payload.
    After updating the withdrawal status to approved, it sends a notification to the client application.

    Returns:
        Response: A JSON response indicating the success or failure of the approval and notification process.
    """
    data = request.json
    wrid = data.get('wrid')
    admin_id = data.get('admin_id')

    # Validate the required fields
    if not wrid or not admin_id:
        logger.warning("Validation failed: 'wrid' and 'admin_id' are required.")
        return jsonify({'error': 'Both wrid and admin_id are required'}), 400

    try:
        # Log the attempt to approve the withdrawal
        logger.info(f"Attempting to approve withdrawal with wrid: {wrid} by admin_id: {admin_id}")

        # Get withdrawal data from the database
        withdrawal_data = Withdrawals.get_withdrawal_data(wrid, admin_id)
        logger.info(f"Retrieved withdrawal data (approved): {withdrawal_data}")

        # Update the withdrawal status to approved in the local database
        Withdrawals.withdrawal_to_approved(wrid, admin_id)

        # Prepare data for the client application
        payload = {
            "wrid": withdrawal_data['wrid'],
            "chat_id": withdrawal_data['chat_id'],
            "firstname": withdrawal_data['firstname'],
            "lastname": withdrawal_data['lastname'],
            "currency": withdrawal_data['currency'],
            "amount": float(withdrawal_data['amount']),
            "net_amount": float(withdrawal_data['net_amount']),
            "fee_percent": float(withdrawal_data['fee_percent']),
            "fee_amount": float(withdrawal_data['fee_amount']),
            "wallet": withdrawal_data['wallet'],
            "timestamp": withdrawal_data['timestamp'].isoformat(),
            "status": withdrawal_data['status'],
            "approved_by_username": withdrawal_data['approved_by_username']
        }

        # Log the payload to be sent to the client application
        logger.info("Sending approval notification to client app with payload: %s", payload)

        # Send the POST request to the client application endpoint
        response = requests.post(f"{Config.CLIENT_HOST}/api/approved_withdrawal", json=payload)

        # Check the response from the client application
        if response.status_code == 200:
            return jsonify({'message': 'Withdrawal successfully approved and notification sent'}), 200
        else:
            logger.error(f"Failed to notify client app. Status code: {response.status_code}. Response: {response.text}")
            return jsonify({'error': 'Failed to notify the client app'}), response.status_code

    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"An error occurred while approving the withdrawal: {e}")
        return jsonify({'error': str(e)}), 500


# main.py

@app.route('/api/withdrawal_to_declined', methods=['POST'])
def withdrawal_to_declined():
    """
    Declines a withdrawal request and notifies the client application.

    This endpoint handles POST requests to decline a specific withdrawal request.
    It requires 'wrid' (withdrawal record ID) and 'admin_id' to be provided in the JSON payload.
    After updating the withdrawal status to declined, it sends a notification to the client application.

    Returns:
        Response: A JSON response indicating the success or failure of the decline and notification process.
    """
    data = request.json
    wrid = data.get('wrid')
    admin_id = data.get('admin_id')

    # Validate the required fields
    if not wrid or not admin_id:
        logger.warning("Validation failed: 'wrid' and 'admin_id' are required.")
        return jsonify({'error': 'Both wrid and admin_id are required'}), 400

    try:
        # Log the attempt to decline the withdrawal
        logger.info(f"Attempting to decline withdrawal with wrid: {wrid} by admin_id: {admin_id}")

        # Retrieve withdrawal data from the database
        withdrawal_data = Withdrawals.get_withdrawal_data(wrid, admin_id)
        if not withdrawal_data:
            time.sleep(3)
            withdrawal_data = Withdrawals.get_withdrawal_data(wrid, admin_id)
            logger.warning("Possible race condition - trying again to obtain withdrawal_data")

        logger.info(f"Retrieved withdrawal data (declined): {withdrawal_data}")

        # Update the withdrawal status to declined in the local database
        Withdrawals.withdrawal_to_declined(wrid, admin_id)

        # Prepare data for the client application
        payload = {
            "wrid": withdrawal_data['wrid'],
            "chat_id": withdrawal_data['chat_id'],
            "firstname": withdrawal_data['firstname'],
            "lastname": withdrawal_data['lastname'],
            "currency": withdrawal_data['currency'],
            "amount": float(withdrawal_data['amount']),
            "net_amount": float(withdrawal_data['net_amount']),
            "fee_percent": float(withdrawal_data['fee_percent']),
            "fee_amount": float(withdrawal_data['fee_amount']),
            "wallet": withdrawal_data['wallet'],
            "timestamp": withdrawal_data['timestamp'].isoformat(),
            "status": withdrawal_data['status'],
            "declined_by_username": withdrawal_data['approved_by_username']  # Assuming it should be 'declined_by_username'
        }

        # Log the payload to be sent to the client application
        logger.info("Sending decline notification to client app with payload: %s", payload)

        # Send the POST request to the client application endpoint
        response = requests.post(f"{Config.CLIENT_HOST}/api/declined_withdrawal", json=payload)

        # Check the response from the client application
        if response.status_code == 200:
            return jsonify({'message': 'Withdrawal successfully declined and notification sent'}), 200
        else:
            logger.error(f"Failed to notify client app. Status code: {response.status_code}. Response: {response.text}")
            return jsonify({'error': 'Failed to notify the client app'}), response.status_code

    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"An error occurred while declining the withdrawal: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/get_withdrawal_data')
def get_withdrawal_data():
    """
    Retrieves withdrawal data based on the provided 'wrid' and 'admin_id'.

    This endpoint handles GET requests to fetch data for a specific withdrawal record.
    The 'wrid' (withdrawal record ID) and 'admin_id' must be provided as query parameters.

    Returns:
        Response: A JSON response containing the withdrawal data or an error message.
    """
    # Extract query parameters from the request
    data = request.args
    wrid = data.get('wrid')
    admin_id = data.get('admin_id')

    # Log the received query parameters
    logger.info(f"Received request with wrid: {wrid} and admin_id: {admin_id}")

    # Validate the required parameters
    if not wrid or not admin_id:
        logger.warning("Validation failed: 'wrid' and 'admin_id' are required.")
        return jsonify({'error': 'wrid and admin_id are required'}), 400

    try:
        # Fetch withdrawal data from the database
        withdrawal = Withdrawals.get_withdrawal_data(wrid, admin_id)
        
        # Convert the result to a dictionary (if not already)
        withdrawal_data = dict(withdrawal)  # Convert RealDictRow to dictionary
        
        # Log the retrieved withdrawal data
        logger.info("Retrieved withdrawal data: %s", withdrawal_data)

        # Return the withdrawal data as a JSON response
        return jsonify(withdrawal_data)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval process
        logger.error(f"An error occurred while retrieving withdrawal data: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/get_withdrawal_record')
def get_withdrawal_record():
    """
    Retrieves a specific withdrawal record based on the provided 'wrid'.

    This endpoint handles GET requests to fetch data for a specific withdrawal record.
    The 'wrid' (withdrawal record ID) must be provided as a query parameter.

    Returns:
        Response: A JSON response containing the withdrawal record data or an error message.
    """
    # Extract query parameters from the request
    data = request.args
    wrid = data.get('wrid')

    # Log the received query parameter
    logger.info(f"Received request with wrid: {wrid}")

    # Validate the required parameter
    if not wrid:
        logger.warning("Validation failed: 'wrid' is required.")
        return jsonify({'error': 'wrid is required'}), 400

    try:
        # Fetch withdrawal record from the database
        withdrawal = Withdrawals.get_withdrawal_record(wrid)
        
        # Convert the result to a dictionary (if not already)
        withdrawal_data = dict(withdrawal)  # Convert RealDictRow to dictionary
        
        # Log the retrieved withdrawal data
        logger.info("Retrieved withdrawal record: %s", withdrawal_data)

        # Return the withdrawal record data as a JSON response
        return jsonify(withdrawal_data)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval process
        logger.error(f"An error occurred while retrieving withdrawal record: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/client_withdrawals')
@login_required
def client_withdrawals():
    """
    Renders the client withdrawals page for the currently logged-in user.

    This endpoint handles GET requests to display the client withdrawals page.
    It retrieves all withdrawal requests and passes them to the `client_withdrawals.html` template
    along with information about the current user.

    Returns:
        Response: The rendered HTML template for client withdrawals.
    """
    try:
        # Fetch all withdrawal requests from the database
        withdrawals = Withdrawals.get_all_withdrawal_requests()
        
        # Log the retrieval of withdrawals and current user information
        logger.info(f"Retrieved withdrawals: {withdrawals}")
        logger.info(f"Current user ID: {current_user.id}")

        # Render the client withdrawals page with the retrieved data
        return render_template('client_withdrawals.html', withdrawals=withdrawals, current_user=current_user)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or rendering process
        logger.error(f"An error occurred while retrieving withdrawals or rendering the page: {e}")

        # Render an error page or return an appropriate response
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/approved_withdrawals')
@login_required
def approved_withdrawals():
    """
    Renders the approved withdrawals page for the currently logged-in user.

    This endpoint handles GET requests to display the approved withdrawals page.
    It retrieves all approved withdrawals and passes them to the `approved_withdrawals.html` template
    along with information about the current user.

    Returns:
        Response: The rendered HTML template for approved withdrawals.
    """
    try:
        # Fetch all approved withdrawal requests from the database
        withdrawals = Withdrawals.get_all_approved_withdrawals()
        
        # Log the retrieval of approved withdrawals and current user information
        logger.info(f"Retrieved approved withdrawals: {withdrawals}")
        logger.info(f"Current user ID: {current_user.id}")

        # Render the approved withdrawals page with the retrieved data
        return render_template('approved_withdrawals.html', withdrawals=withdrawals, current_user=current_user)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or rendering process
        logger.error(f"An error occurred while retrieving approved withdrawals or rendering the page: {e}")

        # Render an error page or return an appropriate response
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/declined_withdrawals')
@login_required
def declined_withdrawals():
    """
    Renders the declined withdrawals page for the currently logged-in user.

    This endpoint handles GET requests to display the declined withdrawals page.
    It retrieves all declined withdrawals and passes them to the `declined_withdrawals.html` template
    along with information about the current user.

    Returns:
        Response: The rendered HTML template for declined withdrawals.
    """
    try:
        # Fetch all declined withdrawal requests from the database
        withdrawals = Withdrawals.get_all_declined_withdrawals()
        
        # Log the retrieval of declined withdrawals and current user information
        logger.info(f"Retrieved declined withdrawals: {withdrawals}")
        logger.info(f"Current user ID: {current_user.id}")

        # Render the declined withdrawals page with the retrieved data
        return render_template('declined_withdrawals.html', withdrawals=withdrawals, current_user=current_user)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or rendering process
        logger.error(f"An error occurred while retrieving declined withdrawals or rendering the page: {e}")

        # Render an error page or return an appropriate response
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/busy_withdrawal')
def busy_withdrawal():
    """
    Checks if a withdrawal request exists for the given 'chat_id'.

    This endpoint handles GET requests to check if there is an existing withdrawal request
    associated with the provided 'chat_id'. It returns the withdrawal record ID if found.

    Query Parameters:
        chat_id (str): The chat ID for which to check the withdrawal request.

    Returns:
        Response: A JSON response containing the withdrawal record ID or an error message.
    """
    # Extract query parameters from the request
    data = request.args
    chat_id = data.get('chat_id')

    # Log the received query parameter
    logger.info(f"Received request with chat_id: {chat_id}")

    # Validate the required parameter
    if not chat_id:
        logger.warning("Validation failed: 'chat_id' is required.")
        return jsonify({'error': 'chat_id is required'}), 400

    try:
        # Check if a withdrawal request exists for the given chat_id
        wrid = Withdrawals.check_withdrawal_request_exists(chat_id)

        # Log the result of the check
        logger.info(f"Withdrawal request ID for chat_id {chat_id}: {wrid}")

        # Return the withdrawal record ID as a JSON response
        return jsonify({'wrid': wrid})
    
    except Exception as e:
        # Log any errors that occur during the check process
        logger.error(f"An error occurred while checking for withdrawal request: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/rollback_withdrawal', methods=['GET'])
@login_required
def rollback_withdrawal():
    """
    Rolls back an approved withdrawal and notifies the client app.

    This endpoint handles GET requests to roll back an approved withdrawal record based on the provided 'wrid'.
    It prepares a payload with the withdrawal details and sends a POST request to the client app to notify about the rollback.

    Query Parameters:
        wrid (str): The withdrawal record ID to roll back.

    Returns:
        Response: A JSON response indicating the success or failure of the rollback operation.
    """
    # Extract query parameters from the request
    data = request.args
    wrid = data.get('wrid')

    # Log the received query parameter
    logger.info(f"Received rollback request for wrid: {wrid}")

    # Validate the required parameter
    if not wrid:
        logger.warning("Validation failed: 'wrid' is required.")
        return jsonify({'error': 'wrid is required'}), 400

    try:
        # Fetch the approved withdrawal record based on the provided wrid
        approved_record = Withdrawals.get_approved_withdrawal_record(wrid=wrid)

        if not approved_record:
            logger.warning(f"No approved record found for wrid: {wrid}")
            return jsonify({'error': 'No approved record found for the provided wrid'}), 404

        # Prepare the payload to notify the client app about the rollback
        payload = {
            "wrid": approved_record['wrid'],
            "chat_id": approved_record['chat_id'],
            "firstname": approved_record['firstname'],
            "lastname": approved_record['lastname'],
            "currency": approved_record['currency'],
            "amount": float(approved_record['amount']),
            "net_amount": float(approved_record['net_amount']),
            "fee_percent": float(approved_record['fee_percent']),
            "fee_amount": float(approved_record['fee_amount']),
            "wallet": approved_record['wallet'],
            "timestamp": approved_record['timestamp'].isoformat(),
            "status": approved_record['status'],
            "approved_timestamp": approved_record['approved_timestamp'].isoformat(),
            "approved_by": approved_record['approved_by']
        }

        # Rollback the withdrawal in the local database
        Withdrawals.rollback_withdrawal(wrid=wrid)

        # Log the rollback action
        logger.info(f"Rolled back withdrawal with wrid: {wrid}")

        # Send the POST request to the client app endpoint
        response = requests.post(f"{Config.CLIENT_HOST}/api/balance_rollback", json=payload)

        # Log the response from the client app
        if response.status_code == 200:
            logger.info("Successfully notified client app about the rollback.")
            return jsonify({'message': 'Rollback successful'}), 200
        else:
            logger.error(f"Failed to notify client app. Status code: {response.status_code}")
            return jsonify({'error': 'Failed to notify the client app'}), response.status_code

    except Exception as e:
        # Log any errors that occur during the process
        logger.error(f"An error occurred while rolling back the withdrawal: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/unidentified_deposits')
@login_required
def unidentified_deposits():
    """
    Renders the declined withdrawals page for the currently logged-in user.

    This endpoint handles GET requests to display the declined withdrawals page.
    It retrieves all declined withdrawals and passes them to the `declined_withdrawals.html` template
    along with information about the current user.

    Returns:
        Response: The rendered HTML template for declined withdrawals.
    """
    try:
        # Log the retrieval of declined withdrawals and current user information
        # logger.info(f"Retrieved unidentified deposits: {withdrawals}")
        logger.info(f"Current user ID: {current_user.id}")

        # Render the declined withdrawals page with the retrieved data
        return render_template('unidentified_deposits.html', current_user=current_user)
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or rendering process
        logger.error(f"An error occurred while retrieving declined withdrawals or rendering the page: {e}")

        # Render an error page or return an appropriate response
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/unidentified_deposits_update', methods=['POST'])
@login_required
def unidentified_deposits_update():
    """
    retrieve unidentified_deposits to update the unidentified_deposits.html page

    Returns:
        Response: The rendered HTML template for declined withdrawals.
    """
    try:
        model = UnidentifiedDeposits()
        # Fetch all declined withdrawal requests from the database
        depositlogs_updated = model.get_unidentified_deposits()
        
        # Log the retrieval of declined withdrawals and current user information
        # logger.info(f"Retrieved unidentified deposits: {withdrawals}")
        logger.info(f"Current user ID: {current_user.id}")

        # Return the unidentified deposits as JSON
        return jsonify({'deposits': depositlogs_updated})
    
    except Exception as e:
        # Log any errors that occur during the data retrieval or processing
        logger.error(f"An error occurred while retrieving unidentified deposits: {e}")

        # Return an error message as JSON
        return jsonify({'error': 'An error occurred while processing the request'}), 500


@app.route('/api/update_depositlogs_refund', methods=['POST'])
@login_required
def update_depositlogs_refund():
    try:
        data= request.get_json()
        # extreact transaction_id and refund_transaction_id
        transaction_id = data.get('transaction_id')
        refund_transaction_id = data.get('refund_transaction_id')

        # udpate Client datbase through integration endpoints
        model = UnidentifiedDeposits()
        result = model.update_depositlogs_refund(transaction_id, refund_transaction_id)
        return jsonify(result)
    
    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while updating refund transaction: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500
    

@app.route('/api/load_ledger_pivot', methods=['GET','POST'])
def load_ledger_pivot():
    try:
        # retrieve the account_name from POST request
        account_name = request.form.get('account_name')

        # validate account_name if not empty
        if not account_name:
            raise ValueError("No account name provided")
        
        clients_model = ReportingData()
        Clients = clients_model.get_clients_list()
        clients_index = {client['account_name']: client for client in Clients}

        client = clients_index.get(account_name)

        if client:
            chat_id = client.get('chat_id')
            firstname = client.get('firstname')
            lastname = client.get('lastname')

        # udpate Client datbase through integration endpoints
        model = ReportingData()
        queryset = model.ledger_report(chat_id, firstname, lastname)

        columns = [
            'primary_key', 'transaction_type', 'chat_id', 'firstname', 'lastname',
            'currency', 'method', 'amount', 'deposit_address', 'eth_transaction_id',
            'eth_transaction_timestamp', 'eth_from_address', 'post_timestamp', 'year', 
            'quarter', 'month', 'week', 'day'
        ]        
        # Convert queryset to Pandas DataFrame
        df = pd.DataFrame(queryset, columns=columns)

        # Ensure timestamp is in datetime format
        df['post_timestamp'] = pd.to_datetime(df['post_timestamp'])
        
        # Add year, quarter, month, week, day columns
        df['year'] = df['post_timestamp'].dt.year
        df['quarter'] = df['post_timestamp'].dt.to_period('Q').astype(str)
        df['month'] = df['post_timestamp'].dt.to_period('M').astype(str)
        df['week'] = df['post_timestamp'].dt.to_period('W').astype(str)
        df['day'] = df['post_timestamp'].dt.date

        # Generate the pivot table and save it to an HTML file
        pivot_file_path = 'static/pivot_table.html'  # Adjust this path
        pivot_ui(df, outfile_path=pivot_file_path)

        # Render the HTML content within your template
        return render_template('report_ledger.html', pivot_file='pivot_table.html', current_user=current_user)

    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while loading report_ledger: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500
    


@app.route('/api/load_ledger_by_transaction_type_pivot', methods=['GET','POST'])
def load_ledger_by_transaction_type_pivot():
    try:
        # retrieve the account_name from POST request
        transaction_type = request.form.get('transaction_type')

        # validate account_name if not empty
        if not transaction_type:
            raise ValueError("No transaction type provided")
        
        # load ledger data by transaction type
        model = ReportingData()
        print(f"model.ledger_by_transaction_type_report({transaction_type})")
        queryset = model.ledger_by_transaction_type_report(transaction_type)
        print(f"\n\n\nQueryset:\n{queryset}\n\n\n")

        columns = [
            'transaction_type', 'chat_id', 'firstname', 'lastname',
            'currency', 'amount', 'eth_transaction_id',
            'eth_transaction_timestamp', 'eth_from_address', 'post_timestamp', 'year', 
            'quarter', 'month', 'week', 'day'
        ]        
   
        # Convert queryset to Pandas DataFrame
        df = pd.DataFrame(queryset, columns=columns)

        # Ensure timestamp is in datetime format
        df['post_timestamp'] = pd.to_datetime(df['post_timestamp'])
        
        # Add year, quarter, month, week, day columns
        df['year'] = df['post_timestamp'].dt.year
        df['quarter'] = df['post_timestamp'].dt.to_period('Q').astype(str)
        df['month'] = df['post_timestamp'].dt.to_period('M').astype(str)
        df['week'] = df['post_timestamp'].dt.to_period('W').astype(str)
        df['day'] = df['post_timestamp'].dt.date

        # Generate the pivot table and save it to an HTML file
        pivot_file_path = 'static/ledger_by_transaction_type_pivot_table.html'  # Adjust this path
        pivot_ui(df, outfile_path=pivot_file_path)

        # Render the HTML content within your template
        return render_template('report_ledger_by_transaction_type.html', pivot_file='ledger_by_transaction_type_pivot_table.html', current_user=current_user)

    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while loading report_ledger: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500    


@app.route('/ledger_presel', methods=['GET', 'POST'])
@login_required
def ledger_presel():
    try:
        model = ReportingData()
        clients_data = model.get_clients_list()
        client_accounts = []
        for client in clients_data:
            client_accounts.append(client['account_name'])
        
        return render_template('ledger_presel.html', clients=client_accounts, current_user=current_user)
   
    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while retrieving ledger_presel.html: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500
    

@app.route('/balances', methods=['GET', 'POST'])
@login_required
def balances():
    try:
        model = ReportingData()
        balances_sum = model.balances_sum()[0]
        formatted_balances_sum = "{:,.2f}".format(balances_sum)

        balances_count = model.balances_count()[0]
        formatted_balances_count = "{:,.2f}".format(balances_count)
        print(f"BALANCES COUNT: {formatted_balances_count}")

        balances_data = model.balances_view()

        # Convert list of lists to list of dictionaries
        balances_view = [
            {
                'chat_id': row[0],
                'firstname': row[1],
                'lastname': row[2],
                'currency': row[3],
                'balance': "{:,.2f}".format(row[4]),
                'creation_date': row[5],
                'last_update_date': row[6],
            }
            for row in balances_data
        ]
        
        return render_template('balances.html', balances_sum=formatted_balances_sum, balances_count=formatted_balances_count, balances_view=balances_view, current_user=current_user)
   
    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while retrieving balances.html: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500



@app.route('/api/ledger_by_transaction_type_presel', methods=['GET', 'POST'])
@login_required
def ledger_by_transaction_type_presel():
    try:
        model = ReportingData()
        transaction_types_data = model.get_transaction_types_list()
        
        return render_template('ledger_by_transaction_type_presel.html', transaction_types=transaction_types_data, current_user=current_user)
   
    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"An error occurred while retrieving ledger_presel.html: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500


if __name__ == '__main__':
    """
    Entry point for running the Flask application.

    This block of code runs the Flask application with debugging enabled and listens on port 5001.
    It is executed when the script is run directly (not imported as a module).

    Note:
        The 'debug=True' option should be used only in development environments. 
        For production, it's recommended to set 'debug=False' and use a production-ready WSGI server.
    """
    try:
        # Run the Flask application
        app.run(debug=True, port=5001)
        logger.info("Flask application started successfully on port 5001.")

    except Exception as e:
        # Log any errors that occur during application startup
        logger.error(f"An error occurred while starting the Flask application: {e}")

