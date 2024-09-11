# models.py
import requests
import psycopg2
from psycopg2 import extras, pool
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
from config import Config
import logging

# Configure logging for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Initialize a connection pool
db_pool = pool.SimpleConnectionPool(
    minconn=100,  # Minimum number of connections in the pool
    maxconn=200,  # Maximum number of connections in the pool
    dbname=Config.DBCONFIG.DBNAME,
    user=Config.DBCONFIG.USER,
    password=Config.DBCONFIG.PASSWORD,
    host=Config.DBCONFIG.HOST,
    port=Config.DBCONFIG.PORT,
    cursor_factory=psycopg2.extras.RealDictCursor
)

# Log the initialization of the connection pool
logger.info("Database connection pool initialized with minconn=100 and maxconn=200.")


class Database:
    """A class to manage database connections and interaction with the connection pool.

    This class provides methods to obtain and release database connections using a connection pool.
    It also offers a method to retrieve the current status of the connection pool.

    Methods:
        get_db_connection():
            Retrieves a connection from the database connection pool. Raises a ValueError if unable to obtain a valid connection.

        close_db_connection(conn):
            Returns a connection to the database connection pool. Raises a ValueError if an error occurs while closing the connection.

        pool_status():
            Provides the current status of the connection pool, including the number of used, closed, open, and free connections, as well as pool limits.

    Attributes:
        db_pool (psycopg2.pool.SimpleConnectionPool): The connection pool instance used to manage database connections.
    """    


    @staticmethod
    def get_db_connection():
        """
        Retrieves a connection from the database connection pool.

        This method obtains a connection from the pool and checks if the connection is valid. 
        If the connection is invalid or cannot be obtained, a ValueError is raised.

        Returns:
            psycopg2.extensions.connection: A valid database connection.

        Raises:
            ValueError: If the connection is invalid or cannot be obtained.
        """
        try:
            conn = db_pool.getconn()

            if not conn or conn.closed != 0:
                raise ValueError("Failed to obtain a valid database connection.")

            # Log successful connection acquisition
            # logger.info("Successfully obtained a new database connection.")
            # Log the current connection pool status
            # logger.info("DB Connection Pool Status: %s", Database.pool_status())

            return conn

        except Exception as e:
            # Log the exception with traceback
            logger.error("Failed to obtain a valid database connection: %s", str(e), exc_info=True)
            raise ValueError(f"Failed to obtain a valid database connection: {e}")


    @staticmethod
    def close_db_connection(conn):
        """
        Returns a database connection to the connection pool.

        This method puts the given connection back into the connection pool for reuse. 
        If an error occurs while returning the connection, it raises a ValueError.

        Args:
            conn (psycopg2.extensions.connection): The database connection to return to the pool.

        Raises:
            ValueError: If there is an error while returning the connection to the pool.
        """
        try:
            if conn is not None:
                db_pool.putconn(conn)
                # Log successful return of the connection
                # logger.info("Database connection returned to the pool.")
            else:
                logger.warning("Attempted to close a None connection.")
        
        except Exception as e:
            # Log the exception with traceback
            logger.error("Error while closing database connection: %s", str(e), exc_info=True)
            raise ValueError(f"Error while closing database connection: {e}")


    @staticmethod
    def pool_status():
        """
        Retrieves the current status of the database connection pool.

        This method provides a snapshot of the connection pool's state, including
        the number of connections that are currently in use, open, closed, and free.

        Returns:
            dict: A dictionary containing the status of the connection pool with the following keys:
                - "minconn": Minimum number of connections in the pool.
                - "maxconn": Maximum number of connections in the pool.
                - "usedconn": Number of connections currently in use.
                - "closedconn": Number of connections that are closed.
                - "openconn": Number of connections that are open.
                - "freeconn": Number of connections that are free in the pool.
        """
        try:
            status = {
                "minconn": db_pool.minconn,
                "maxconn": db_pool.maxconn,
                "usedconn": len(db_pool._used),
                "closedconn": sum(1 for conn in db_pool._used.values() if conn.closed != 0),
                "openconn": sum(1 for conn in db_pool._used.values() if conn.closed == 0),
                "freeconn": len(db_pool._pool),
            }
            
            # Log the pool status
            # logger.info("Connection Pool Status: %s", status)
            
            return status
        
        except Exception as e:
            # Log the exception with traceback
            logger.error("Error while retrieving connection pool status: %s", str(e), exc_info=True)
            raise ValueError(f"Error while retrieving connection pool status: {e}")


class User(UserMixin):
    """
    Represents a user in the system.

    Inherits from `UserMixin` to provide default implementations for user authentication features.

    Attributes:
        id (int): The unique identifier for the user.
        username (str): The username of the user.
        password_hash (str): The hashed password of the user.

    Methods:
        get_by_username(username):
            Retrieves a User object by the specified username.

        get_by_id(user_id):
            Retrieves a User object by the specified user ID.

        create(username, password):
            Creates a new user with the specified username and password.

        check_password(password):
            Checks if the provided password matches the stored hashed password.

        login(username, password):
            Logs in the user with the specified username and password.

        logout(username):
            Logs out the user with the specified username.

        create_user(username, password_hash):
            Creates a new user with the specified username and password hash.
    """    
    
    def __init__(self, id, username, password_hash):
        """
        Initializes a User object with the specified attributes.

        Args:
            id (int): The unique identifier for the user.
            username (str): The username of the user.
            password_hash (str): The hashed password of the user.

        Raises:
            ValueError: If any of the arguments are invalid (e.g., None or empty).
        """
        if not id or not username:
            logger.error("Invalid initialization parameters: id=%s, username=%s, password_hash=%s", id, username, password_hash)
            raise ValueError("Invalid user attributes provided")

        self.id = id
        self.username = username
        self.password_hash = password_hash

        # logger.info("User object initialized: id=%s, username=%s", id, username)


    @staticmethod
    def get_by_username(username):
        """
        Retrieves a user from the database based on their username.

        Args:
            username (str): The username of the user to retrieve.

        Returns:
            User: A User object if the user is found, otherwise None.

        Raises:
            ValueError: If `username` is not provided.
            Exception: If an error occurs while retrieving the user from the database.
        """
        if not username:
            logger.error("Username is required but was not provided.")
            raise ValueError("Username is required")

        try:
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.callproc('get_user_by_username', (username,))
            result = cur.fetchone()
            Database.close_db_connection(conn)
            cur.close()

            if result:
                logger.info("User found: %s", result['username'])
                return User(result['id'], result['username'], result['password'])
            else:
                logger.info("No user found with username: %s", username)
                return None
        except Exception as e:
            logger.error("An error occurred while retrieving user by username: %s", e)
            raise


    @staticmethod
    def get_by_id(user_id):
        """
        Retrieves a user from the database based on their user ID.

        Args:
            user_id (int): The ID of the user to retrieve.

        Returns:
            User: A User object if the user is found, otherwise None.

        Raises:
            ValueError: If `user_id` is not provided.
            Exception: If an error occurs while retrieving the user from the database.
        """
        if not user_id:
            logger.error("User ID is required but was not provided.")
            raise ValueError("User ID is required")

        try:
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.callproc('get_user_by_id', (user_id,))
            result = cur.fetchone()
            Database.close_db_connection(conn)
            cur.close()

            if result:
                logger.info("User found with ID: %s", user_id)
                return User(result['user_id'], result['user_name'], result['password_hash'])  # Adjust column names accordingly
            else:
                logger.info("No user found with ID: %s", user_id)
                return None
        except Exception as e:
            logger.error("An error occurred while retrieving user by ID: %s", e)
            raise


    @staticmethod
    def create(username, password):
        """
        Creates a new user in the database with the provided username and password.

        Args:
            username (str): The username of the new user.
            password (str): The password for the new user.

        Returns:
            User: A User object representing the newly created user.

        Raises:
            ValueError: If `username` or `password` is not provided.
            Exception: If an error occurs while creating the user in the database.
        """
        if not username or not password:
            logger.error("Username and password are required but were not provided.")
            raise ValueError("Username and password are required")

        try:
            conn = Database.get_db_connection()
            password_hash = generate_password_hash(password)
            cur = conn.cursor()
            cur.callproc('create_user', (username, password_hash))
            conn.commit()
            Database.close_db_connection(conn)
            cur.close()

            logger.info("User created successfully with username: %s", username)
            return User(None, username, password_hash)
        except Exception as e:
            logger.error("An error occurred while creating the user: %s", e)
            raise


    def check_password(self, password):
        """
        Verifies if the provided password matches the stored hashed password.

        Args:
            password (str): The plain text password to check.

        Returns:
            bool: True if the password matches the stored hashed password, otherwise False.

        Raises:
            ValueError: If `password` is not provided.
        """
        if not password:
            logger.error("Password is required but was not provided.")
            raise ValueError("Password is required")

        try:
            is_valid = check_password_hash(self.password_hash, password)
            logger.info("Password check for user ID %s: %s", self.id, "successful" if is_valid else "failed")
            return is_valid
        except Exception as e:
            logger.error("An error occurred while checking the password for user ID %s: %s", self.id, e)
            raise


    @staticmethod
    def login(username, password):
        """
        Authenticates a user by their username and password.

        Args:
            username (str): The username of the user to authenticate.
            password (str): The plain text password of the user.

        Raises:
            ValueError: If `username` or `password` is not provided.
            RuntimeError: If an error occurs while accessing the database or executing the login procedure.
        """
        if not username:
            logger.error("Username is required but was not provided.")
            raise ValueError("Username is required")
        if not password:
            logger.error("Password is required but was not provided.")
            raise ValueError("Password is required")

        try:
            # Get a database connection
            conn = Database.get_db_connection()
            
            # Create a cursor object
            cur = conn.cursor()

            # Call the stored procedure to log in the user
            cur.callproc('login', (username, password))

            # Commit the transaction
            conn.commit()

            # Close the database connection
            Database.close_db_connection(conn)
            cur.close()

            logger.info("User %s successfully logged in.", username)

        except Exception as e:
            logger.error("An error occurred while logging in user %s: %s", username, e)
            if conn:
                Database.close_db_connection(conn)
            raise RuntimeError("Failed to execute login procedure.") from e


    @staticmethod
    def logout(username):
        """
        Logs out a user by their username.

        Args:
            username (str): The username of the user to log out.

        Raises:
            ValueError: If `username` is not provided.
            RuntimeError: If an error occurs while accessing the database or executing the logout procedure.
        """
        if not username:
            logger.error("Username is required but was not provided.")
            raise ValueError("Username is required")

        conn = None
        try:
            # Get a database connection
            conn = Database.get_db_connection()
            
            # Create a cursor object
            cur = conn.cursor()

            # Call the stored procedure to log out the user
            cur.callproc('logout', (username,))

            # Commit the transaction
            conn.commit()

            # Close the cursor
            cur.close()

            logger.info("User %s successfully logged out.", username)

        except Exception as e:
            logger.error("An error occurred while logging out user %s: %s", username, e)
            if conn:
                Database.close_db_connection(conn)
            raise RuntimeError("Failed to execute logout procedure.") from e
        finally:
            # Ensure the connection is closed in case of an exception
            if conn:
                Database.close_db_connection(conn)


    @staticmethod
    def create_user(username, password_hash):
        """
        Creates a new user with the provided username and hashed password.

        Args:
            username (str): The username of the new user.
            password_hash (str): The hashed password for the new user.

        Raises:
            ValueError: If `username` or `password_hash` is not provided.
            RuntimeError: If an error occurs while accessing the database or executing the user creation procedure.
        """
        if not username or not password_hash:
            logger.error("Username and password hash are required but were not provided.")
            raise ValueError("Both username and password hash are required")

        conn = None
        try:
            # Get a database connection
            conn = Database.get_db_connection()
            
            # Create a cursor object
            cur = conn.cursor()

            # Call the stored procedure to create a new user
            cur.callproc('create_user', (username, password_hash))

            # Commit the transaction
            conn.commit()

            # Close the cursor
            cur.close()

            logger.info("User %s successfully created.", username)

        except Exception as e:
            logger.error("An error occurred while creating user %s: %s", username, e)
            if conn:
                Database.close_db_connection(conn)
            raise RuntimeError("Failed to execute user creation procedure.") from e
        finally:
            # Ensure the connection is closed in case of an exception
            if conn:
                Database.close_db_connection(conn)


class Withdrawals:
    """
    A class to handle withdrawal-related operations involving requests, approvals, rejections, and rollbacks.

    This class provides static methods for interacting with withdrawal records in the database, including:
    - Creating new withdrawal requests
    - Retrieving all withdrawal requests or filtering by their status (approved, declined)
    - Locking and unlocking withdrawal records
    - Changing the status of withdrawals to approved or declined
    - Retrieving detailed data about specific withdrawals
    - Checking if a withdrawal request exists
    - Rolling back a withdrawal

    Methods:
        create_withdrawal_request(chat_id, firstname, lastname, currency, amount, wallet):
            Creates a new withdrawal request in the database.

        get_all_withdrawal_requests():
            Retrieves all withdrawal requests from the database.

        get_all_approved_withdrawals():
            Retrieves all approved withdrawal requests from the database.

        get_all_declined_withdrawals():
            Retrieves all declined withdrawal requests from the database.

        lock_withdrawal_record(wrid, admin_id):
            Locks a specific withdrawal record to prevent further modifications.

        unlock_withdrawal_record(wrid):
            Unlocks a specific withdrawal record to allow modifications.

        withdrawal_to_approved(wrid, admin_id):
            Changes the status of a specific withdrawal record to approved.

        withdrawal_to_declined(wrid, admin_id):
            Changes the status of a specific withdrawal record to declined.

        get_withdrawal_data(wrid, admin_id):
            Retrieves detailed data for a specific withdrawal record.

        get_withdrawal_record(wrid):
            Retrieves a specific withdrawal record.

        get_approved_withdrawal_record(wrid):
            Retrieves a specific approved withdrawal record.

        check_withdrawal_request_exists(chat_id):
            Checks if a withdrawal request exists for the given chat ID.

        rollback_withdrawal(wrid):
            Rolls back a specific withdrawal request.

    """


    @staticmethod
    def create_withdrawal_request(chat_id, firstname, lastname, currency, amount, wallet):
        """
        Creates a new withdrawal request in the database with the specified details.

        Args:
            chat_id (str): The chat ID associated with the withdrawal request.
            firstname (str): The first name of the individual making the withdrawal request.
            lastname (str): The last name of the individual making the withdrawal request.
            currency (str): The currency in which the withdrawal is requested.
            amount (float): The amount of money to withdraw.
            wallet (str): The wallet to which the withdrawal should be applied.

        Raises:
            ValueError: If there is an issue with the database connection or execution.
        """
        conn = None
        cur = None
        try:
            conn = Database.get_db_connection()
            cur = conn.cursor()
            
            # Calculate the fee percent from configuration
            fee_percent = Config.WITHDRAWAL_FEE
            
            # Execute the stored procedure to create a withdrawal request
            cur.execute(
                "CALL create_withdrawal_request(%s::VARCHAR, %s::VARCHAR, %s::VARCHAR, %s::VARCHAR, %s::NUMERIC, %s::NUMERIC, %s::VARCHAR);",
                (chat_id, firstname, lastname, currency, amount, fee_percent, wallet)
            )
            
            # Commit the transaction to the database
            conn.commit()
            
            logger.info(f"Successfully created withdrawal request for chat_id: {chat_id}")
        
        except Exception as e:
            logger.error(f"Error creating withdrawal request: {e}")
            raise ValueError(f"Error creating withdrawal request: {e}")
        
        finally:
            # Ensure that the cursor and connection are closed properly
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)


    def get_all_withdrawal_requests():
        """
        Retrieves all withdrawal requests from the database.

        Returns:
            list: A list of dictionaries representing all withdrawal requests.
                  Each dictionary contains the details of a withdrawal request.

        Raises:
            ValueError: If there is an issue with the database connection or execution.
        """
        conn = None
        cur = None
        try:
            conn = Database.get_db_connection()
            cur = conn.cursor()
            
            # Call the stored procedure to get all withdrawal requests
            cur.callproc('get_all_withdrawal_requests')
            
            # Fetch all results from the executed procedure
            withdrawals = cur.fetchall()
            
            #logger.info("Successfully retrieved all withdrawal requests.")
            return withdrawals
        
        except Exception as e:
            logger.error(f"Error retrieving withdrawal requests: {e}")
            raise ValueError(f"Error retrieving withdrawal requests: {e}")
        
        finally:
            # Ensure that the cursor and connection are closed properly
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)
    

    def get_all_approved_withdrawals():
        """
        Retrieves all approved withdrawal requests from the database.

        Returns:
            list: A list of dictionaries representing all approved withdrawal requests.
                  Each dictionary contains the details of an approved withdrawal request.

        Raises:
            ValueError: If there is an issue with the database connection or execution.
        """
        conn = None
        cur = None
        try:
            conn = Database.get_db_connection()
            cur = conn.cursor()
            
            # Call the stored procedure to get all approved withdrawal requests
            cur.callproc('get_all_approved_withdrawals')
            
            # Fetch all results from the executed procedure
            withdrawals = cur.fetchall()
            
            #logger.info("Successfully retrieved all approved withdrawal requests.")
            return withdrawals
        
        except Exception as e:
            logger.error(f"Error retrieving approved withdrawal requests: {e}")
            raise ValueError(f"Error retrieving approved withdrawal requests: {e}")
        
        finally:
            # Ensure that the cursor and connection are closed properly
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)
    

    def get_all_declined_withdrawals():
        """
        Retrieves all declined withdrawal requests from the database.

        Returns:
            list: A list of dictionaries representing all declined withdrawal requests.
                  Each dictionary contains the details of a declined withdrawal request.

        Raises:
            ValueError: If there is an issue with the database connection or execution.
        """
        conn = None
        cur = None
        try:
            conn = Database.get_db_connection()
            cur = conn.cursor()
            
            # Call the stored procedure to get all declined withdrawal requests
            cur.callproc('get_all_declined_withdrawals')
            
            # Fetch all results from the executed procedure
            withdrawals = cur.fetchall()
            
            #logger.info("Successfully retrieved all declined withdrawal requests.")
            return withdrawals
        
        except Exception as e:
            logger.error(f"Error retrieving declined withdrawal requests: {e}")
            raise ValueError(f"Error retrieving declined withdrawal requests: {e}")
        
        finally:
            # Ensure that the cursor and connection are closed properly
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)
   

    @staticmethod
    def lock_withdrawal_record(wrid, admin_id):
        """
        Lock a withdrawal record to prevent further modifications.

        This method acquires a database connection, executes a stored procedure to lock a
        withdrawal record identified by the provided `wrid` for the given `admin_id`,
        and then commits the transaction. The connection and cursor are properly closed
        even if an error occurs.

        Args:
            wrid (str): The withdrawal request ID to be locked.
            admin_id (str): The ID of the administrator performing the action.

        Raises:
            ValueError: If there's an error obtaining or closing the database connection,
                        or if the procedure execution fails.
        """
        conn = None
        cur = None
        try:
            conn = Database.get_db_connection()
            cur = conn.cursor()
            fee_percent = Config.WITHDRAWAL_FEE

            # Execute the stored procedure to lock the record
            cur.execute('CALL lock_record(%s, %s)', (wrid, admin_id))
            conn.commit()
            logger.info(f"Successfully locked withdrawal record {wrid} by admin {admin_id}.")

        except Exception as e:
            logger.error(f"Error while locking withdrawal record {wrid}: {e}")
            raise ValueError(f"Error while locking withdrawal record {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)


    @staticmethod
    def unlock_withdrawal_record(wrid):
        """
        Unlock a previously locked withdrawal record.

        This method acquires a database connection, executes a stored procedure to unlock a
        withdrawal record identified by the provided `wrid`, and then commits the transaction. 
        The connection and cursor are properly closed even if an error occurs.

        Args:
            wrid (str): The withdrawal request ID to be unlocked.

        Raises:
            ValueError: If there's an error obtaining or closing the database connection,
                        or if the procedure execution fails.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor()
            fee_percent = Config.WITHDRAWAL_FEE

            # Execute the stored procedure to unlock the record
            cur.execute('CALL unlock_record(%s)', (wrid,))
            conn.commit()
            logger.info(f"Successfully unlocked withdrawal record {wrid}.")

        except Exception as e:
            logger.error(f"Error while unlocking withdrawal record {wrid}: {e}")
            raise ValueError(f"Error while unlocking withdrawal record {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)

    
    @staticmethod
    def withdrawal_to_approved(wrid, admin_id):
        """
        This method transfers a withdrawal request from the `withdrawal_requests` table 
        to the `approved_withdrawals` table, effectively marking it as approved.

        This method acquires a database connection, executes a stored procedure to move
        the withdrawal request identified by `wrid` into the approved table, and commits the transaction. 
        The connection and cursor are properly closed even if an error occurs.

        Args:
            wrid (str): The withdrawal request ID to be approved.
            admin_id (str): The ID of the admin approving the request.

        Raises:
            ValueError: If there's an error obtaining or closing the database connection,
                        or if the procedure execution fails.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor()

            # Execute the stored procedure to mark the withdrawal as approved
            cur.callproc('withdrawal_to_approved', (wrid, admin_id))
            conn.commit()
            logger.info(f"Successfully marked withdrawal request {wrid} as approved by admin {admin_id}.")

        except Exception as e:
            logger.error(f"Error while marking withdrawal request {wrid} as approved: {e}")
            raise ValueError(f"Error while marking withdrawal request {wrid} as approved: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)
    

    @staticmethod
    def withdrawal_to_declined(wrid, admin_id):
        """
        Mark a withdrawal request as declined.

        This method transfers a withdrawal request from the `withdrawal_requests` table 
        to the `declined_withdrawals` table, effectively marking it as declined. It acquires 
        a database connection, executes a stored procedure to perform the update, and commits 
        the transaction. The connection and cursor are properly closed even if an error occurs.

        Args:
            wrid (str): The ID of the withdrawal request to be declined.
            admin_id (str): The ID of the admin performing the action.

        Raises:
            ValueError: If an error occurs during database operations or if the connection 
                        cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor()

            # Execute the stored procedure to mark the withdrawal as declined
            cur.callproc('withdrawal_to_declined', (wrid, admin_id))
            conn.commit()
            logger.info(f"Successfully marked withdrawal request {wrid} as declined by admin {admin_id}.")

        except Exception as e:
            logger.error(f"Error while marking withdrawal request {wrid} as declined: {e}")
            raise ValueError(f"Error while marking withdrawal request {wrid} as declined: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)


    @staticmethod
    def get_withdrawal_data(wrid, admin_id):
        """
        Retrieve detailed information for a specific withdrawal request.

        This method queries the database to get detailed information about a withdrawal request
        using its ID (`wrid`) and the ID of the admin (`admin_id`). The method uses a stored procedure
        and returns the result as a dictionary with column names as keys.

        Args:
            wrid (str): The ID of the withdrawal request whose data is to be retrieved.
            admin_id (str): The ID of the admin requesting the data.

        Returns:
            dict or None: Returns a dictionary containing withdrawal data if found, or `None` 
                          if no data is found.

        Raises:
            ValueError: If there is an error during the database operation or if the connection 
                        cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Execute the stored procedure to fetch withdrawal data
            cur.callproc('get_withdrawal_data', (wrid, admin_id))
            result = cur.fetchone()
            logger.info(f"Retrieved withdrawal data for request {wrid} by admin {admin_id}.")

            return result

        except Exception as e:
            logger.error(f"Error while retrieving withdrawal data for request {wrid}: {e}")
            raise ValueError(f"Error while retrieving withdrawal data for request {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)    


    @staticmethod
    def get_withdrawal_record(wrid):
        """
        Retrieve a specific withdrawal record by its ID.

        This method queries the database to get information about a withdrawal record 
        using its ID (`wrid`). The method uses a stored procedure and returns the 
        result as a dictionary with column names as keys.

        Args:
            wrid (str): The ID of the withdrawal record to be retrieved.

        Returns:
            dict or None: Returns a dictionary containing the withdrawal record if found, 
                          or `None` if no record is found.

        Raises:
            ValueError: If there is an error during the database operation or if the 
                        connection cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Execute the stored procedure to fetch withdrawal record
            cur.callproc('get_withdrawal_record', (wrid,))
            result = cur.fetchone()
            logger.info(f"Retrieved withdrawal record for request {wrid}.")

            return result

        except Exception as e:
            logger.error(f"Error while retrieving withdrawal record for request {wrid}: {e}")
            raise ValueError(f"Error while retrieving withdrawal record for request {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)
    

    @staticmethod
    def get_approved_withdrawal_record(wrid):
        """
        Retrieve a specific approved withdrawal record by its ID.

        This method queries the database to get information about an approved withdrawal record 
        using its ID (`wrid`). The method uses a stored procedure and returns the 
        result as a dictionary with column names as keys.

        Args:
            wrid (str): The ID of the approved withdrawal record to be retrieved.

        Returns:
            dict or None: Returns a dictionary containing the approved withdrawal record if found, 
                          or `None` if no record is found.

        Raises:
            ValueError: If there is an error during the database operation or if the 
                        connection cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Execute the stored procedure to fetch approved withdrawal record
            cur.callproc('get_approved_withdrawal_record', (wrid,))
            result = cur.fetchone()
            logger.info(f"Retrieved approved withdrawal record for request {wrid}.")

            return result

        except Exception as e:
            logger.error(f"Error while retrieving approved withdrawal record for request {wrid}: {e}")
            raise ValueError(f"Error while retrieving approved withdrawal record for request {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)


    @staticmethod
    def check_withdrawal_request_exists(chat_id):
        """
        Check if a withdrawal request exists for a given chat ID.

        This method queries the database to determine if a withdrawal request exists
        for the specified chat ID. It uses a stored procedure and returns the result 
        indicating the presence of a withdrawal request.

        Args:
            chat_id (str): The chat ID to check for an existing withdrawal request.

        Returns:
            bool or None: Returns `True` if a withdrawal request exists for the chat ID, 
                          `False` if no request is found, or `None` if an error occurs.

        Raises:
            ValueError: If there is an error during the database operation or if the 
                        connection cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Execute the stored procedure to check for withdrawal request
            cur.callproc('check_withdrawal_request_exists', (chat_id,))
            result = cur.fetchone()

            # Log the result of the check operation
            logger.info(f"Checked withdrawal request existence for chat_id {chat_id}: {result}")

            if result:
                return result.get('check_withdrawal_request_exists')

            return None

        except Exception as e:
            logger.error(f"Error while checking withdrawal request existence for chat_id {chat_id}: {e}")
            raise ValueError(f"Error while checking withdrawal request existence for chat_id {chat_id}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)    


    @staticmethod
    def rollback_withdrawal(wrid):
        """
        Rollback a withdrawal request by its ID.

        This method calls a stored procedure to rollback a withdrawal request for
        the specified withdrawal request ID (WRID). The operation is committed to 
        the database.

        Args:
            wrid (int): The ID of the withdrawal request to rollback.

        Returns:
            None

        Raises:
            ValueError: If there is an error during the database operation or if the 
                        connection cannot be obtained or closed properly.
        """
        conn = None
        cur = None
        try:
            # Obtain a database connection from the pool
            conn = Database.get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Execute the stored procedure to rollback the withdrawal
            cur.execute('CALL rollback_withdrawal(%s)', (wrid,))
            conn.commit()

            # Log successful rollback operation
            logger.info(f"Successfully rolled back withdrawal with ID {wrid}")

        except Exception as e:
            logger.error(f"Error while rolling back withdrawal with ID {wrid}: {e}")
            raise ValueError(f"Error while rolling back withdrawal with ID {wrid}: {e}")

        finally:
            if cur:
                cur.close()
            if conn:
                Database.close_db_connection(conn)        


    def get_id(self):
        """
        Retrieve the ID of the current withdrawal instance.

        This method returns the ID of the withdrawal request as a string.

        Returns:
            str: The ID of the withdrawal request.

        Notes:
            This method assumes that the `id` attribute of the `Withdrawals` instance
            is set and available. It does not perform any database operations or
            external calls.

        Example:
            >>> withdrawal = Withdrawals()
            >>> withdrawal.id = 123
            >>> withdrawal.get_id()
            '123'
        """
        try:
            # Convert the ID to a string and return
            return str(self.id)
        except AttributeError as e:
            logger.error(f"Error retrieving ID: {e}")
            raise ValueError("ID attribute not set or available.")
        

class UnidentifiedDeposits:
    def get_unidentified_deposits(self):
        """
        Retrieves all unidentified deposits from the external API.

        Returns:
            list: A list of dictionaries representing all unidentified deposits.

        Raises:
            ValueError: If there is an issue with the API request.
        """
        url = f"{Config.CLIENT_HOST}/api/get_unidentified_deposits"
        
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an error for bad status codes
            deposits = response.json()  # Parse the response as JSON

            # Clean single quotes from relevant fields
            for deposit in deposits:
                if 'transaction_id' in deposit:
                    deposit['transaction_id'] = deposit['transaction_id'].replace("'", '')
                if 'from_address' in deposit:
                    deposit['from_address'] = deposit['from_address'].replace("'", '')
                if 'to_address' in deposit:
                    deposit['to_address'] = deposit['to_address'].replace("'", '')

            
            #logger.info("Successfully retrieved all unidentified deposits.")
            return deposits
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving unidentified deposits: {e}")
            raise ValueError(f"Error retrieving unidentified deposits: {e}")        
    

    def update_depositlogs_refund(self, transaction_id: str, refund_transaction_id: str):
        url = f"{Config.CLIENT_HOST}/api/update_depositlogs_refund"

        # Prepare the payload for the POST request
        payload = {
            'p_transaction_id': transaction_id.replace("'", ""),
            'p_refund_transaction_id': refund_transaction_id
        }

        try:
            # POST request
            result = requests.post(url, json=payload)

            # Check for HTTP errors
            result.raise_for_status()

            # Return the JSON response from the FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error updating refund transaction: {e}")
            raise ValueError(f"Error updating refund transaction: {e}")
        

class ReportingData:
    def get_clients_list(self):
        url = f"{Config.RETURNS_HOST}/api/get_clients_list"

        try:
            result = requests.post(url)

            # Check for HTTP errors
            result.raise_for_status()

            print(result)

            # return response from FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading clients list: {e}")
            raise ValueError(f"Error loading clients list: {e}")


    def ledger_report(self, chat_id: int, firstname: str, lastname: str):
        url = f"{Config.RETURNS_HOST}/api/ledger_view"

        try:
            # Make a POST request with account_name as part of the JSON body
            response = requests.post(url, params={
                'chat_id': chat_id,
                'firstname': firstname,
                'lastname': lastname
            })
            # Check for HTTP errors
            response.raise_for_status()

            # Return response from FastAPI server
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading ledger view data: {e}")
            raise ValueError(f"Error loading ledger view data: {e}")
        

    def ledger_by_transaction_type_report(self, transaction_type: str):
        url = f"{Config.RETURNS_HOST}/api/ledger_by_transaction_type"

        try:
            # Make a POST request with account_name as part of the JSON body
            response = requests.post(url, params={
                'transaction_type': transaction_type
            })
            # Check for HTTP errors
            response.raise_for_status()

            # Return response from FastAPI server
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading ledger by transaction type view data: {e}")
            raise ValueError(f"Error loading ledger by transaction type view data: {e}")
    


    def get_transaction_types_list(self):
        url = f"{Config.RETURNS_HOST}/api/ledger_get_transaction_types"

        try:
            result = requests.post(url)

            # Check for HTTP errors
            result.raise_for_status()

            # return response from FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading clients list: {e}")
            raise ValueError(f"Error loading clients list: {e}")
        

    def balances_sum(self):
        url = f"{Config.RETURNS_HOST}/api/balances_sum"

        try:
            result = requests.post(url)

            # Check for HTTP errors
            result.raise_for_status()

            # return response from FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading blances sum: {e}")
            

    def balances_count(self):
        url = f"{Config.RETURNS_HOST}/api/balances_count"

        try:
            result = requests.post(url)

            # Check for HTTP errors
            result.raise_for_status()

            # return response from FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading balances count: {e}")



    def balances_view(self):
        url = f"{Config.RETURNS_HOST}/api/balances_view"

        try:
            result = requests.post(url)

            # Check for HTTP errors
            result.raise_for_status()

            # return response from FastAPI server
            return result.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading clients list: {e}")
            raise ValueError(f"Error loading clients list: {e}")
