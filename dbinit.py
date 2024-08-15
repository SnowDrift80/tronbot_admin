# db_init.py

"""
dbinit.py

This module initializes the database for the admin app by creating necessary tables and stored procedures.
It should be executed as a standalone script after the database has been created and `config.py` has been updated
with the appropriate database credentials. This script must be run before starting `main.py`.

**Import Section**:
- Imports necessary libraries and modules for database operations and configuration management.

Imports:
    - psycopg2: A PostgreSQL database adapter for Python. Used for connecting to and interacting with the PostgreSQL database.
    - Config (from config): Custom configuration module that provides database credentials and other configuration settings.
    - generate_password_hash (from werkzeug.security): A utility for securely hashing passwords. Used for creating secure passwords for database users.

"""

import logging
import psycopg2
from config import Config
from werkzeug.security import generate_password_hash

# Configure logging at the global level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class DBInit:
    """
    DBInit class initializes the database for the admin app.

    The DBInit class consists of several methods to set up the database structure,
    including creating tables, stored procedures, and functions. It is executed as 
    a standalone script after the database has been created and `config.py` has been 
    updated with the database credentials.

    Methods:
        __init__():
            Initializes the DBInit class by readying the Config data.
        
        connect():
            Establishes a connection to the PostgreSQL database using the configuration
            data from the Config class.
        
        execute_script(script):
            Executes a single SQL script provided as a parameter. This method is used to
            run the SQL commands for creating tables, functions, and procedures.
        
        initialize_database():
            Executes a series of methods to create the database structure. This method
            runs each SQL script in sequence to set up the required tables, stored 
            procedures, and functions.

        Other Methods:
            The class contains numerous additional methods, each responsible for 
            creating a specific table, stored procedure, or function in the database. 
            These methods are called by the `initialize_database` method to set up the 
            entire database structure.

            Example Methods:
                - create_users_table()
                - create_sessions_table()
                - create_withdrawal_requests_table()
                - create_approved_withdrawals_table()
                - create_declined_withdrawals_table()
                - create_create_withdrawal_request_procedure()
                - create_lock_record_procedure()
                - create_unlock_record_procedure()
                - create_admin_user()
                - create_withdrawal_to_approved_function()
                - create_withdrawal_to_declined_function()
                - create_get_withdrawal_data_function()
                - create_login_function()
                - create_logout_function()
                - create_get_user_by_username_function()
                - create_get_user_by_id_function()
                - create_create_user_function()
                - create_get_all_withdrawal_requests_function()
                - create_get_all_approved_withdrawals_function()
                - create_get_all_declined_withdrawals_function()
                - create_check_withdrawal_request_exists_function()
                - create_get_withdrawal_record_function()
                - create_rollback_withdrawal_procedure()
                - create_get_approved_withdrawal_record_function()
                - Additional methods as needed for database initialization.
    """
    
    def __init__(self):
        """
        Initialize the DBInit class.

        This constructor method initializes the DBInit class by loading the
        configuration data from the Config class. This configuration data
        includes the database credentials and other necessary settings.

        Raises:
            Exception: If there is an error in loading the configuration.
        """
        try:
            # Load database configuration from the Config class
            self.db_config = Config
            logging.info('Configuration loaded successfully.')
        except Exception as e:
            logging.error('Failed to load configuration: %s', e)
            raise


    def connect(self):
        """
        Establish a connection to the PostgreSQL database.

        This method creates and returns a connection object to the PostgreSQL
        database using the credentials and configuration specified in the Config
        class.

        Returns:
            psycopg2.extensions.connection: A connection object to the PostgreSQL database.

        Raises:
            psycopg2.DatabaseError: If there is an issue connecting to the database.
        """
        try:
            # Establish and return the database connection
            connection = psycopg2.connect(
                dbname=self.db_config.DBCONFIG.DBNAME,
                user=self.db_config.DBCONFIG.USER,
                password=self.db_config.DBCONFIG.PASSWORD,
                host=self.db_config.DBCONFIG.HOST,
                port=self.db_config.DBCONFIG.PORT
            )
            logging.info('Database connection established successfully.')
            return connection
        except psycopg2.DatabaseError as e:
            logging.error('Failed to connect to the database: %s', e)
            raise


    def execute_script(self, script):
        """
        Execute a single SQL script.

        This method establishes a connection to the PostgreSQL database, 
        executes the provided SQL script, and commits the transaction.

        Args:
            script (str): The SQL script to be executed.

        Raises:
            psycopg2.DatabaseError: If there is an issue executing the script.
        """
        try:
            # Establish a database connection
            with self.connect() as conn:
                # Create a cursor to execute the script
                with conn.cursor() as cursor:
                    # Execute the provided SQL script
                    cursor.execute(script)
                    # Commit the transaction
                    conn.commit()
            logging.info('%s SQL script executed successfully.', script)
        except psycopg2.DatabaseError as e:
            logging.error('Failed to execute script: %s', e)
            raise

    def initialize_database(self):
        """
        Run all the SQL scripts to initialize the database.

        This method executes a series of SQL scripts to create tables, 
        stored procedures, and functions necessary for the application.

        Raises:
            psycopg2.DatabaseError: If there is an issue executing any of the scripts.
        """
        try:
            # Log the start of the initialization process
            logging.info('Initializing database: starting the process.')

            # Execute SQL scripts to create tables
            logging.info('Initializing database: creating tables.')
            self.execute_script(self.create_users_table())
            self.execute_script(self.create_sessions_table())
            self.execute_script(self.create_withdrawal_requests_table())
            self.execute_script(self.create_approved_withdrawals_table())
            self.execute_script(self.create_declined_withdrawals_table())
            
            # Execute SQL scripts to create stored procedures
            logging.info('Initializing database: creating stored procedures.')
            self.execute_script(self.create_create_withdrawal_request_procedure())
            self.execute_script(self.create_lock_record_procedure())
            self.execute_script(self.create_unlock_record_procedure())
            self.execute_script(self.create_admin_user())
            
            # Execute SQL scripts to create functions
            logging.info('Initializing database: creating functions.')
            self.execute_script(self.create_withdrawal_to_approved_function())
            self.execute_script(self.create_withdrawal_to_declined_function())
            self.execute_script(self.create_get_withdrawal_data_function())
            self.execute_script(self.create_login_function())
            self.execute_script(self.create_logout_function())
            self.execute_script(self.create_get_user_by_username_function())
            self.execute_script(self.create_get_user_by_id_function())
            self.execute_script(self.create_create_user_function())
            self.execute_script(self.create_get_all_withdrawal_requests_function())
            self.execute_script(self.create_get_all_approved_withdrawals_function())
            self.execute_script(self.create_get_all_declined_withdrawals_function())
            self.execute_script(self.create_check_withdrawal_request_exists_function())
            self.execute_script(self.create_get_withdrawal_record_function())
            self.execute_script(self.create_rollback_withdrawal_procedure())
            self.execute_script(self.create_get_approved_withdrawal_record_function())

            # Log the successful completion of the initialization process
            logging.info('Database initialization completed successfully.')
        except psycopg2.DatabaseError as e:
            # Log any errors that occur during the initialization process
            logging.error('Database initialization failed: %s', e)
            raise
        

    @staticmethod
    def create_users_table():
        """
        Generate the SQL script to create the 'users' table.

        This table will store user information, including a unique identifier (id),
        a unique username, and a password.

        Returns:
            str: The SQL script to create the 'users' table.
        """
        return """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        """

    @staticmethod
    def create_sessions_table():
        """
        Generate the SQL script to create the 'sessions' table.

        This table will store session information for users, including a unique identifier (id),
        the user associated with the session (user_id), and the timestamp of when the session was created (login_time).
        It also establishes a foreign key relationship with the 'users' table to ensure referential integrity.

        Returns:
            str: The SQL script to create the 'sessions' table.
        """
        return """
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """
    

    @staticmethod
    def create_withdrawal_requests_table():
        """
        Generate the SQL script to create the 'withdrawal_requests' table.

        This table will store information related to withdrawal requests, including a unique identifier (wrid),
        chat ID, personal information (firstname, lastname), currency type, amounts (total, net, fee), and wallet information.
        It also includes a timestamp for when the request was made, a status field to track the request's state, 
        and a reference to an admin who might lock the request.

        Returns:
            str: The SQL script to create the 'withdrawal_requests' table.
        """
        return """
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            wrid SERIAL PRIMARY KEY,
            chat_id VARCHAR(100) NOT NULL,
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10) DEFAULT 'USDT',
            amount NUMERIC(20, 6) NOT NULL,
            net_amount NUMERIC(20, 6) NOT NULL,
            fee_percent NUMERIC(5, 2) NOT NULL,
            fee_amount NUMERIC(20, 6) NOT NULL,
            wallet VARCHAR(100) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'Pending',
            locked_by INT -- reference to admin ID who holds the lock
        );
        """
    

    @staticmethod
    def create_approved_withdrawals_table():
        """
        Generate the SQL script to create the 'approved_withdrawals' table.

        This table stores information about approved withdrawal requests, including a unique identifier (wrid),
        chat ID, personal details (firstname, lastname), currency, amounts (total, net, fee), and wallet information.
        It includes timestamps for when the request was made and when it was approved, a status field indicating 
        that the request is approved, and a reference to the admin who approved the withdrawal.

        Returns:
            str: The SQL script to create the 'approved_withdrawals' table.
        """
        return """
        CREATE TABLE IF NOT EXISTS approved_withdrawals (
            wrid SERIAL PRIMARY KEY,
            chat_id VARCHAR(100) NOT NULL,
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10) DEFAULT 'USDT',
            amount NUMERIC(20, 6) NOT NULL,
            net_amount NUMERIC(20, 6) NOT NULL,
            fee_percent NUMERIC(5, 2) NOT NULL,
            fee_amount NUMERIC(20, 6) NOT NULL,
            wallet VARCHAR(100) NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            approved_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'Approved',
            approved_by INT -- reference to admin ID who approved the withdrawal
        );
        """
    

    @staticmethod
    def create_declined_withdrawals_table():
        """
        Generate the SQL script to create the 'declined_withdrawals' table.

        This table records information about withdrawal requests that were declined. It includes fields for a unique 
        identifier (wrid), chat ID, personal details (firstname, lastname), currency, amounts (total, net, fee), 
        and wallet information. It also tracks timestamps for when the request was made and when it was declined, 
        with a status field indicating that the request was declined. Additionally, it includes a reference to the admin 
        who declined the request.

        Returns:
            str: The SQL script to create the 'declined_withdrawals' table.
        """
        return """
        CREATE TABLE IF NOT EXISTS declined_withdrawals (
            wrid SERIAL PRIMARY KEY,
            chat_id VARCHAR(100) NOT NULL,
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10) DEFAULT 'USDT',
            amount NUMERIC(20, 6) NOT NULL,
            net_amount NUMERIC(20, 6) NOT NULL,
            fee_percent NUMERIC(5, 2) NOT NULL,
            fee_amount NUMERIC(20, 6) NOT NULL,
            wallet VARCHAR(100) NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            declined_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'Declined',
            declined_by INT -- reference to admin ID who declined the withdrawal
        );
        """


    @staticmethod
    def create_lock_record_procedure():
        """
        Generate the SQL script to create the 'lock_record' stored procedure.

        This stored procedure is used to lock a record in the 'withdrawal_requests' table, marking it as being worked 
        on by an admin. It updates the 'locked_by' field with the ID of the admin user who has locked the record and 
        changes the 'status' of the record to 'LOCKED'.

        Parameters:
            in_wrid (INT): The unique identifier of the withdrawal request to be locked.
            in_admin_id (INT): The ID of the admin user who is locking the record.

        Returns:
            str: The SQL script to create the 'lock_record' stored procedure.
        """
        return """
        CREATE OR REPLACE PROCEDURE lock_record(
            in_wrid INT,
            in_admin_id INT
        )
        LANGUAGE SQL
        AS $$
        UPDATE withdrawal_requests
        SET locked_by = in_admin_id,
            status = 'LOCKED'
        WHERE wrid = in_wrid;
        $$;
        """
    

    @staticmethod
    def create_unlock_record_procedure():
        """
        Generate the SQL script to create the 'unlock_record' stored procedure.

        This stored procedure is used to unlock a record in the 'withdrawal_requests' table that was previously locked 
        by an admin. It updates the 'locked_by' field to `NULL` and resets the 'status' of the record to 'Pending'.

        Parameters:
            in_wrid (INT): The unique identifier of the withdrawal request to be unlocked.

        Returns:
            str: The SQL script to create the 'unlock_record' stored procedure.
        """
        return """
        CREATE OR REPLACE PROCEDURE unlock_record(
            in_wrid INT
        )
        LANGUAGE SQL
        AS $$
        UPDATE withdrawal_requests
        SET locked_by = NULL,
            status = 'Pending'
        WHERE wrid = in_wrid;
        $$;
        """


    @staticmethod
    def create_create_withdrawal_request_procedure():
        """
        Generate the SQL script to create the 'create_withdrawal_request' stored procedure.

        This stored procedure adds a new withdrawal request to the 'withdrawal_requests' table. It calculates the fee 
        amount and net amount based on the provided parameters, and inserts a new record into the table.

        Parameters:
            p_chat_id (VARCHAR(100)): The chat ID associated with the withdrawal request.
            p_firstname (VARCHAR(100)): The first name of the individual making the request.
            p_lastname (VARCHAR(100)): The last name of the individual making the request.
            p_currency (VARCHAR(10)): The currency of the withdrawal request (e.g., 'USDT').
            p_amount (NUMERIC(20, 6)): The total amount requested for withdrawal.
            p_fee_percent (NUMERIC(5, 2)): The percentage of the fee applied to the withdrawal amount.
            p_wallet (VARCHAR(100)): The wallet address associated with the withdrawal request.

        Returns:
            str: The SQL script to create the 'create_withdrawal_request' stored procedure.
        """
        return """
        CREATE OR REPLACE PROCEDURE create_withdrawal_request(
            p_chat_id VARCHAR(100),
            p_firstname VARCHAR(100),
            p_lastname VARCHAR(100),
            p_currency VARCHAR(10),
            p_amount NUMERIC(20, 6),
            p_fee_percent NUMERIC(5, 2),
            p_wallet VARCHAR(100)
        )
        LANGUAGE plpgsql
        AS $$
        DECLARE
            v_fee_amount NUMERIC(20, 6);
            v_net_amount NUMERIC(20, 6);
        BEGIN
            -- Calculate fee amount and net amount
            v_fee_amount := p_amount * p_fee_percent / 100.0;
            v_net_amount := p_amount - v_fee_amount;

            -- Insert into withdrawal_requests table
            INSERT INTO withdrawal_requests (chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet)
            VALUES (p_chat_id, p_firstname, p_lastname, p_currency, p_amount, v_net_amount, p_fee_percent, v_fee_amount, p_wallet);

            -- Optionally, return some result or confirmation
            -- RETURNING wrid, timestamp;  -- Example: return inserted ID and timestamp
        END;
        $$;
        """
    

    @staticmethod
    def create_withdrawal_to_approved_function():
        """
        Generate the SQL script to create the 'withdrawal_to_approved' stored function.

        This stored function moves a withdrawal request from the 'withdrawal_requests' table to the 'approved_withdrawals' table.
        It copies the relevant details of the request and sets its status to 'Approved', associating it with an admin user who 
        approved the request. After the transfer, the original record is deleted from the 'withdrawal_requests' table.

        Parameters:
            p_wrid (INTEGER): The ID of the withdrawal request to be moved to the 'approved_withdrawals' table.
            admin_id (INTEGER): The ID of the admin user who approved the withdrawal request.

        Returns:
            VOID: This function does not return any value but performs the operation of moving the record and updating statuses.
        """
        return """
        CREATE OR REPLACE FUNCTION withdrawal_to_approved(p_wrid INTEGER, admin_id INTEGER) RETURNS VOID AS $$
        BEGIN
            INSERT INTO approved_withdrawals (wrid, chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet, timestamp, status, approved_by)
            SELECT p_wrid, chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet, timestamp, 'Approved', admin_id
            FROM withdrawal_requests
            WHERE withdrawal_requests.wrid = p_wrid;
            
            DELETE FROM withdrawal_requests WHERE wrid = p_wrid;
        END;
        $$ LANGUAGE plpgsql;
        """
    

    @staticmethod
    def create_withdrawal_to_declined_function():
        """
        Generate the SQL script to create the 'withdrawal_to_declined' stored function.

        This stored function moves a withdrawal request from the 'withdrawal_requests' table to the 'declined_withdrawals' table.
        It transfers the details of the request and updates its status to 'Declined', while associating it with an admin user
        who declined the request. After transferring, the original record is deleted from the 'withdrawal_requests' table.

        Parameters:
            p_wrid (INTEGER): The ID of the withdrawal request to be moved to the 'declined_withdrawals' table.
            admin_id (INTEGER): The ID of the admin user who declined the withdrawal request.

        Returns:
            VOID: This function does not return any value but executes the operation of moving the record and updating statuses.
        """
        return """
        CREATE OR REPLACE FUNCTION withdrawal_to_declined(p_wrid INT, admin_id INT) RETURNS VOID AS $$
        BEGIN
            INSERT INTO declined_withdrawals (wrid, chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet, timestamp, status, declined_by)
            SELECT p_wrid, chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet, timestamp, 'Declined', admin_id
            FROM withdrawal_requests
            WHERE withdrawal_requests.wrid = p_wrid;
            
            DELETE FROM withdrawal_requests WHERE wrid = p_wrid;
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_admin_user():
        """
        Generate the SQL script to create an admin user in the 'users' table if it does not already exist.

        This script inserts a new user into the 'users' table with the username and hashed password of the admin user. 
        If the user with the specified username already exists, the script will not perform any action due to the `ON CONFLICT DO NOTHING` clause.

        The username and password for the admin user are fetched from the configuration settings. The password is securely hashed using `generate_password_hash`.

        Returns:
            str: The SQL script for creating the admin user. This script includes an `INSERT` statement with a conflict handling clause.
        """
        admin_username = Config.DBCONFIG.ADMIN_USERNAME
        admin_password = generate_password_hash(Config.DBCONFIG.ADMIN_PASSWORD)
        return f"""
        INSERT INTO users (username, password)
        VALUES ('{admin_username}', '{admin_password}')
        ON CONFLICT DO NOTHING;
        """


    @staticmethod
    def create_login_function():
        """
        Generate the SQL script to create a function that validates user login credentials.

        This function, named `login`, checks whether a user with the given `username` and `password` exists in the `users` table. It returns `TRUE` if the user exists and the password matches, otherwise `FALSE`.

        The function performs the following:
        - Accepts a `username` of type `VARCHAR` and a `password` of type `TEXT`.
        - Checks the `users` table for a matching `username` and `password`.
        - Uses the `EXISTS` clause to determine if there is at least one record with the provided credentials.

        Returns:
            str: The SQL script for creating the `login` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION login(username VARCHAR, password TEXT)
        RETURNS BOOLEAN AS $$
        BEGIN
            RETURN EXISTS (
                SELECT 1 FROM users
                WHERE username = username AND password = password
            );
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_logout_function():
        """
        Generate the SQL script to create a function that handles user logout operations.

        This function, named `logout`, is intended to perform necessary actions when a user logs out. As a placeholder, it currently does not perform any specific operations but provides a structure for implementing logout functionality.

        The function is designed to:
        - Accept a `user_id` of type `INT` as an argument, which represents the ID of the user logging out.
        - Optionally, you could extend this function to update the `last_logout_time` in the `sessions` table or perform other logout-related tasks.

        Returns:
            str: The SQL script for creating the `logout` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION logout(user_id INT)
        RETURNS VOID AS $$
        BEGIN
            -- Perform logout operations if needed
            -- E.g., update last_logout_time in sessions table
            -- This function can be expanded based on your logout requirements
            -- For simplicity, it's left as a placeholder
            RETURN;
        END;
        $$ LANGUAGE plpgsql;
        """
    
    @staticmethod
    def create_get_user_by_username_function():
        """
        Generate the SQL script to create a function that retrieves user details by username.

        This function, named `get_user_by_username`, retrieves user information based on the provided username.

        The function is designed to:
        - Accept a parameter `p_username` of type `VARCHAR`, which represents the username of the user whose details are to be retrieved.
        - Return a table with columns for `id`, `username`, and `password` of the user.

        The function performs the following:
        - Queries the `users` table to find the user with the specified `p_username`.
        - Returns the `id`, `username`, and `password` of the user in a result table.

        Returns:
            str: The SQL script for creating the `get_user_by_username` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_user_by_username(p_username VARCHAR)
        RETURNS TABLE (id INT, username VARCHAR, password TEXT) AS $$
        BEGIN
            RETURN QUERY
            SELECT u.id, u.username, u.password
            FROM users u
            WHERE u.username = p_username;
        END;
        $$ LANGUAGE plpgsql;
        """    
    

    @staticmethod
    def create_get_user_by_id_function():
        """
        Generate the SQL script to create a function that retrieves user details by user ID.

        This function, named `get_user_by_id`, retrieves user information based on the provided user ID.

        The function is designed to:
        - Accept a parameter `p_user_id` of type `INT`, which represents the ID of the user whose details are to be retrieved.
        - Return a table with columns for `user_id`, `user_name`, and `password_hash` of the user.

        The function performs the following:
        - Queries the `users` table to find the user with the specified `p_user_id`.
        - Returns the `id` as `user_id`, `username` as `user_name`, and `password_hash` in a result table.

        Returns:
            str: The SQL script for creating the `get_user_by_id` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_user_by_id(p_user_id INT)
        RETURNS TABLE (user_id INT, user_name VARCHAR(100), password_hash TEXT) AS $$
        BEGIN
            RETURN QUERY
            SELECT id AS user_id, username AS user_name, password_hash
            FROM users
            WHERE id = p_user_id;
        END;
        $$ LANGUAGE plpgsql;
        """
    

    @staticmethod
    def create_create_user_function():
        """
        Generate the SQL script to create a function that inserts a new user into the `users` table.

        This function, named `create_user`, allows for the creation of a new user record with a given username and password hash.

        The function is designed to:
        - Accept two parameters:
        - `p_username` of type `VARCHAR(100)`, which is the username of the new user.
        - `p_password_hash` of type `TEXT`, which is the hashed password of the new user.
        - Insert these parameters into the `users` table.

        The function performs the following:
        - Executes an `INSERT` statement to add a new record into the `users` table with the provided `username` and `password_hash`.

        Returns:
            str: The SQL script for creating the `create_user` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION create_user(p_username VARCHAR(100), p_password_hash TEXT)
        RETURNS VOID AS $$
        BEGIN
            INSERT INTO users (username, password)
            VALUES (p_username, p_password_hash);
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_get_all_withdrawal_requests_function():
        """
        Generate the SQL script to create a function that retrieves all withdrawal requests from the `withdrawal_requests` table.

        This function, named `get_all_withdrawal_requests`, retrieves and returns all records from the `withdrawal_requests` table.

        The function is designed to:
        - Return a table with columns matching those in the `withdrawal_requests` table:
        - `wrid` of type `INT`
        - `chat_id` of type `VARCHAR(100)`
        - `firstname` of type `VARCHAR(100)`
        - `lastname` of type `VARCHAR(100)`
        - `currency` of type `VARCHAR(10)`
        - `amount` of type `NUMERIC(20, 6)`
        - `net_amount` of type `NUMERIC(20, 6)`
        - `fee_percent` of type `NUMERIC(5, 2)`
        - `fee_amount` of type `NUMERIC(20, 6)`
        - `wallet` of type `VARCHAR(100)`
        - `timestamp` of type `TIMESTAMP`
        - `status` of type `VARCHAR(20)`
        - `locked_by` of type `INT`
        - Execute a `SELECT` statement to retrieve all records from the `withdrawal_requests` table.
        - Order the results by the `timestamp` column in ascending order.

        Returns:
            str: The SQL script for creating the `get_all_withdrawal_requests` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_all_withdrawal_requests()
        RETURNS TABLE (
            wrid INT,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            status VARCHAR(20),
            locked_by INT
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                w.wrid, w.chat_id, w.firstname, w.lastname, w.currency, w.amount, w.net_amount, w.fee_percent, w.fee_amount, w.wallet, w."timestamp", w.status, w.locked_by
            FROM 
                withdrawal_requests w
            ORDER BY
                w."timestamp" ASC;  -- Order by timestamp ascending
        END;
        $$ LANGUAGE plpgsql;
        """
    

    @staticmethod
    def create_get_withdrawal_data_function():
        """
        Generate the SQL script to create a function that retrieves detailed withdrawal request data.

        This function, named `get_withdrawal_data`, returns the details of a specific withdrawal request along with the username of the admin who has locked the record. It is intended for use in confirming withdrawal details back to the client.

        The function is designed to:
        - Return a table with columns matching those required for withdrawal request details and admin information:
        - `wrid` of type `INTEGER`
        - `chat_id` of type `VARCHAR(100)`
        - `firstname` of type `VARCHAR(100)`
        - `lastname` of type `VARCHAR(100)`
        - `currency` of type `VARCHAR(10)`
        - `amount` of type `NUMERIC(20, 6)`
        - `net_amount` of type `NUMERIC(20, 6)`
        - `fee_percent` of type `NUMERIC(5, 2)`
        - `fee_amount` of type `NUMERIC(20, 6)`
        - `wallet` of type `VARCHAR(100)`
        - `timestamp` of type `TIMESTAMP`
        - `status` of type `VARCHAR(20)`
        - `approved_by_username` of type `VARCHAR(100)`, representing the username of the admin who has locked the record.
        - Execute a `SELECT` statement to retrieve the record from the `withdrawal_requests` table and join with the `users` table to fetch the admin's username.
        - The query ensures that only the record with the matching `wrid` and admin ID is returned.

        Parameters:
            p_wrid (INTEGER): The unique identifier of the withdrawal request.
            p_admin_id (INTEGER): The unique identifier of the admin who has locked the record.

        Returns:
            str: The SQL script for creating the `get_withdrawal_data` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_withdrawal_data(p_wrid INTEGER, p_admin_id INTEGER)
        RETURNS TABLE (
            wrid INTEGER,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            status VARCHAR(20),
            approved_by_username VARCHAR(100)
        )
        AS $$
        BEGIN
            RETURN QUERY
            SELECT
                wr.wrid,
                wr.chat_id,
                wr.firstname,
                wr.lastname,
                wr.currency,
                wr.amount,
                wr.net_amount,
                wr.fee_percent,
                wr.fee_amount,
                wr.wallet,
                wr."timestamp",
                wr.status,
                u.username AS approved_by_username
            FROM
                withdrawal_requests wr
            JOIN
                users u ON wr.locked_by = u.id  -- Assuming locked_by references admin ID in users table
            WHERE
                wr.wrid = p_wrid
                AND u.id = p_admin_id;
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_get_withdrawal_record_function():
        """
        Generate the SQL script to create a function that retrieves a specific withdrawal request record.

        This function, named `get_withdrawal_record`, returns detailed information about a withdrawal request based on its unique identifier (`wrid`). It provides all relevant fields related to the withdrawal request.

        The function is designed to:
        - Return a table with columns that include:
        - `wrid` of type `INTEGER`
        - `chat_id` of type `VARCHAR(100)`
        - `firstname` of type `VARCHAR(100)`
        - `lastname` of type `VARCHAR(100)`
        - `currency` of type `VARCHAR(10)`
        - `amount` of type `NUMERIC(20, 6)`
        - `net_amount` of type `NUMERIC(20, 6)`
        - `fee_percent` of type `NUMERIC(5, 2)`
        - `fee_amount` of type `NUMERIC(20, 6)`
        - `wallet` of type `VARCHAR(100)`
        - `timestamp` of type `TIMESTAMP`
        - `status` of type `VARCHAR(20)`
        - Execute a `SELECT` statement to retrieve the record from the `withdrawal_requests` table based on the provided `wrid`.

        Parameters:
            p_wrid (INTEGER): The unique identifier of the withdrawal request.

        Returns:
            str: The SQL script for creating the `get_withdrawal_record` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_withdrawal_record(p_wrid INTEGER)
        RETURNS TABLE (
            wrid INTEGER,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            status VARCHAR(20)
        )
        AS $$
        BEGIN
            RETURN QUERY
            SELECT
                wr.wrid,
                wr.chat_id,
                wr.firstname,
                wr.lastname,
                wr.currency,
                wr.amount,
                wr.net_amount,
                wr.fee_percent,
                wr.fee_amount,
                wr.wallet,
                wr."timestamp",
                wr.status
            FROM
                withdrawal_requests wr
            WHERE
                wr.wrid = p_wrid;
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_get_all_approved_withdrawals_function():
        """
        Generate the SQL script to create a function that retrieves all approved withdrawal records.

        This function, named `get_all_approved_withdrawals`, returns a record set containing all approved withdrawal requests from the `approved_withdrawals` table. The results are ordered by the `approved_timestamp` in descending order and are limited to the most recent 1000 records.

        The function is designed to:
        - Return a table with columns that include:
        - `wrid` of type `INT`
        - `chat_id` of type `VARCHAR(100)`
        - `firstname` of type `VARCHAR(100)`
        - `lastname` of type `VARCHAR(100)`
        - `currency` of type `VARCHAR(10)`
        - `amount` of type `NUMERIC(20, 6)`
        - `net_amount` of type `NUMERIC(20, 6)`
        - `fee_percent` of type `NUMERIC(5, 2)`
        - `fee_amount` of type `NUMERIC(20, 6)`
        - `wallet` of type `VARCHAR(100)`
        - `timestamp` of type `TIMESTAMP`
        - `approved_timestamp` of type `TIMESTAMP`
        - `status` of type `VARCHAR(20)`
        - `approved_by_username` of type `VARCHAR(100)` (Username of the admin who approved the withdrawal)
        - Execute a `SELECT` statement to retrieve the records from the `approved_withdrawals` table, join with the `users` table to include the admin username who approved the withdrawal.

        Returns:
            str: The SQL script for creating the `get_all_approved_withdrawals` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_all_approved_withdrawals()
        RETURNS TABLE (
            wrid INT,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            approved_timestamp TIMESTAMP,
            status VARCHAR(20),
            approved_by_username VARCHAR(100)
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                a.wrid, a.chat_id, a.firstname, a.lastname, a.currency, a.amount, a.net_amount, a.fee_percent, a.fee_amount, a.wallet, a."timestamp", a.approved_timestamp, a.status, u.username AS approved_by_username
            FROM 
                approved_withdrawals a
            JOIN
                users u ON a.approved_by = u.id
            ORDER BY
                a.approved_timestamp DESC  -- Order by approved_timestamp ascending
            LIMIT 1000;  -- Limit the result set to 1000 rows
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_get_all_declined_withdrawals_function():
        """
        Generate the SQL script to create a function that retrieves all declined withdrawal records.

        This function, named `get_all_declined_withdrawals`, returns a record set containing all declined withdrawal requests from the `declined_withdrawals` table. The results are ordered by the `declined_timestamp` in descending order and are limited to the most recent 1000 records.

        The function is designed to:
        - Return a table with columns that include:
        - `wrid` of type `INT`
        - `chat_id` of type `VARCHAR(100)`
        - `firstname` of type `VARCHAR(100)`
        - `lastname` of type `VARCHAR(100)`
        - `currency` of type `VARCHAR(10)`
        - `amount` of type `NUMERIC(20, 6)`
        - `net_amount` of type `NUMERIC(20, 6)`
        - `fee_percent` of type `NUMERIC(5, 2)`
        - `fee_amount` of type `NUMERIC(20, 6)`
        - `wallet` of type `VARCHAR(100)`
        - `timestamp` of type `TIMESTAMP`
        - `declined_timestamp` of type `TIMESTAMP`
        - `status` of type `VARCHAR(20)`
        - `declined_by_username` of type `VARCHAR(100)` (Username of the admin who declined the withdrawal)
        - Execute a `SELECT` statement to retrieve the records from the `declined_withdrawals` table, join with the `users` table to include the admin username who declined the withdrawal.

        Returns:
            str: The SQL script for creating the `get_all_declined_withdrawals` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_all_declined_withdrawals()
        RETURNS TABLE (
            wrid INT,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            declined_timestamp TIMESTAMP, 
            status VARCHAR(20),
            declined_by_username VARCHAR(100)
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                d.wrid, d.chat_id, d.firstname, d.lastname, d.currency, d.amount, d.net_amount, d.fee_percent, d.fee_amount, d.wallet, d."timestamp", d.declined_timestamp, d.status, u.username AS declined_by_username
            FROM 
                declined_withdrawals d
            JOIN
                users u ON d.declined_by = u.id
            ORDER BY
                d.declined_timestamp DESC  -- Order by declined_timestamp ascending
            LIMIT 1000;  -- Limit the result set to 1000 rows
        END;
        $$ LANGUAGE plpgsql;
        """


    @staticmethod
    def create_check_withdrawal_request_exists_function():
        """
        Generate the SQL script to create a function that checks for existing withdrawal requests by chat_id.

        This function, named `check_withdrawal_request_exists`, determines if there is already an active withdrawal request with a given `chat_id` in the `withdrawal_requests` table. It returns the `wrid` of the existing request if found, or `NULL` if no matching request exists.

        The function performs the following:
        - Takes a single parameter:
        - `p_chat_id` of type `VARCHAR(100)`: The chat ID to check for existing withdrawal requests.
        - Returns an `INTEGER`, which represents the `wrid` (withdrawal request ID) of an existing request, or `NULL` if no matching request is found.

        Returns:
            str: The SQL script for creating the `check_withdrawal_request_exists` function. This script uses PL/pgSQL to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION check_withdrawal_request_exists(p_chat_id VARCHAR(100))
        RETURNS INTEGER  -- Assuming wrid is of type SERIAL (INTEGER)
        AS $$
        DECLARE
            v_wrid INTEGER;
        BEGIN
            SELECT wrid INTO v_wrid
            FROM withdrawal_requests
            WHERE chat_id = p_chat_id;

            RETURN v_wrid;
        END;
        $$ LANGUAGE plpgsql;
        """
    

    @staticmethod
    def create_rollback_withdrawal_procedure():
        """
        Generate the SQL script to create a procedure for rolling back an approved withdrawal.

        This stored procedure, named `rollback_withdrawal`, handles the rollback of an approved withdrawal request by performing the following operations:
        - **Insert**: It selects an approved withdrawal record from the `approved_withdrawals` table based on the provided `wrid_param` and inserts it into the `withdrawal_requests` table. The status of the new request is set to 'Pending' and `locked_by` is set to `NULL`.
        - **Delete**: It then deletes the record from the `approved_withdrawals` table.

        The procedure is executed by a rollback button in the approved withdrawals view, allowing the reversion of an approved withdrawal to its initial request state.

        Parameters:
            wrid_param (INT): The ID of the approved withdrawal record to be rolled back.

        Returns:
            str: The SQL script for creating the `rollback_withdrawal` procedure. This script uses PL/pgSQL to define the procedure.
        """
        return """
        CREATE OR REPLACE PROCEDURE rollback_withdrawal(IN wrid_param INT)
        LANGUAGE plpgsql
        AS $$
        BEGIN
            -- Insert the record into withdrawal_requests table
            INSERT INTO withdrawal_requests (chat_id, firstname, lastname, currency, amount, net_amount, fee_percent, fee_amount, wallet, "timestamp", status, locked_by)
            SELECT 
                chat_id, 
                firstname, 
                lastname, 
                currency, 
                amount, 
                net_amount, 
                fee_percent, 
                fee_amount, 
                wallet, 
                "timestamp", 
                'Pending', 
                NULL -- locked_by is set to NULL as it is a new request
            FROM approved_withdrawals 
            WHERE wrid = wrid_param;

            -- Delete the record from approved_withdrawals table
            DELETE FROM approved_withdrawals 
            WHERE wrid = wrid_param;
            
        END;
        $$;
        """


    @staticmethod
    def create_get_approved_withdrawal_record_function():
        """
        Generate the SQL script to create a function for retrieving an approved withdrawal record by its ID.

        This stored function, named `get_approved_withdrawal_record`, retrieves details of an approved withdrawal 
        from the `approved_withdrawals` table based on the provided `p_wrid` parameter. The function returns a table 
        with the following columns:
        - `wrid`: The unique identifier for the withdrawal request.
        - `chat_id`: The chat ID associated with the withdrawal request.
        - `firstname`: The first name of the requester.
        - `lastname`: The last name of the requester.
        - `currency`: The currency of the withdrawal request.
        - `amount`: The total amount requested.
        - `net_amount`: The amount after fees.
        - `fee_percent`: The fee percentage applied.
        - `fee_amount`: The fee amount deducted.
        - `wallet`: The wallet address used for the withdrawal.
        - `timestamp`: The timestamp when the withdrawal was requested.
        - `approved_timestamp`: The timestamp when the withdrawal was approved.
        - `status`: The status of the withdrawal request (should be 'Approved').
        - `approved_by`: The ID of the admin who approved the withdrawal.

        Parameters:
            p_wrid (INTEGER): The ID of the approved withdrawal record to retrieve.

        Returns:
            str: The SQL script for creating the `get_approved_withdrawal_record` function. This script uses PL/pgSQL 
            to define the function.
        """
        return """
        CREATE OR REPLACE FUNCTION get_approved_withdrawal_record(p_wrid INTEGER)
        RETURNS TABLE (
            wrid INTEGER,
            chat_id VARCHAR(100),
            firstname VARCHAR(100),
            lastname VARCHAR(100),
            currency VARCHAR(10),
            amount NUMERIC(20, 6),
            net_amount NUMERIC(20, 6),
            fee_percent NUMERIC(5, 2),
            fee_amount NUMERIC(20, 6),
            wallet VARCHAR(100),
            "timestamp" TIMESTAMP,
            approved_timestamp TIMESTAMP,
            status VARCHAR(20),
            approved_by INT
        )
        AS $$
        BEGIN
            RETURN QUERY
            SELECT
                aw.wrid,
                aw.chat_id,
                aw.firstname,
                aw.lastname,
                aw.currency,
                aw.amount,
                aw.net_amount,
                aw.fee_percent,
                aw.fee_amount,
                aw.wallet,
                aw."timestamp",
                aw.approved_timestamp,
                aw.status,
                aw.approved_by
            FROM
                approved_withdrawals aw
            WHERE
                aw.wrid = p_wrid;
        END;
        $$ LANGUAGE plpgsql;
        """


if __name__ == "__main__":
    # Create an instance of the DBInit class to handle database initialization.
    db_initializer = DBInit()
    
    try:
        # Initialize the database by running all required SQL scripts.
        db_initializer.initialize_database()
        logging.info("Database initialization completed successfully.")
    except Exception as e:
        # Log the exception with traceback for debugging purposes.
        logging.error(f"An error occurred during database initialization: {e}", exc_info=True)
        # Optionally, you can raise the exception if you want to halt execution.
        raise