import os

class Config:
    # Generate a random secret key for session security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess-this-key'
    
    # CONNECTION STRING: mysql+pymysql://username:password@localhost/databasename
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://medivault_admin:galvin@localhost/medivault_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Where we store the master encryption key (In real life, use a Key Vault)
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or b'Fua5_OMYbZYxxSWz6hINsCaIJ5U55r9jEPr9pkC-IvU='