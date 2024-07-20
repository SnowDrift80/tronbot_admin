# config.py

import logging

# Setting up the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Config:
    """
    Configuration class for the application.

    Attributes:
        SECRET_KEY (str): Secret key for session management and security.
        WITHDRAWAL_FEE (float): Withdrawal fee percentage.
        CLIENT_HOST (str): Client host URL.
    """
    
    # Hardcoded configuration values
    SECRET_KEY = 'a_really_long_and_random_secret_key'
    WITHDRAWAL_FEE = 10.00  # Withdrawal fee in percent, two decimals
    CLIENT_HOST = "http://localhost:8000"

    class DBCONFIG:
        """
        Database configuration class.

        Attributes:
            DBNAME (str): Name of the database.
            USER (str): Database username.
            PASSWORD (str): Database password.
            HOST (str): Database host address.
            PORT (str): Database port number.
            ADMIN_USERNAME (str): Admin username for the database.
            ADMIN_PASSWORD (str): Admin password for the database.
        """
        
        # Hardcoded database configuration values
        DBNAME = 'OrcaAdmin'
        USER = 'orcaadmin'
        PASSWORD = 'txm9272'
        HOST = 'psql15.hq.rvg'
        PORT = '5432'
        ADMIN_USERNAME = 'snow'
        ADMIN_PASSWORD = '1234'

# Log the loaded configuration for debugging purposes
logger.info("Configuration loaded: SECRET_KEY=%s, WITHDRAWAL_FEE=%.2f, CLIENT_HOST=%s", 
            Config.SECRET_KEY, Config.WITHDRAWAL_FEE, Config.CLIENT_HOST)
logger.info("Database configuration loaded: DBNAME=%s, USER=%s, HOST=%s, PORT=%s", 
            Config.DBCONFIG.DBNAME, Config.DBCONFIG.USER, Config.DBCONFIG.HOST, Config.DBCONFIG.PORT)
