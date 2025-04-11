import uuid
import bcrypt
import jwt
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

class UserManagement:
    def __init__(self, 
                 mongo_uri: str = 'mongodb://localhost:27017', 
                 database_name: str = 'threat_intelligence_db',
                 jwt_secret: str = None,
                 jwt_expiration: int = 3600):
        """
        Initialize User Management system
        
        :param mongo_uri: MongoDB connection URI
        :param database_name: Name of the database
        :param jwt_secret: Secret key for JWT token generation
        :param jwt_expiration: Token expiration time in seconds
        """
        # Logging setup
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Database connection
        try:
            self.client = MongoClient(mongo_uri)
            self.db = self.client[database_name]
            self.users_collection = self.db['users']
            
            # Create unique index for email
            self.users_collection.create_index('email', unique=True)
        except Exception as e:
            self.logger.error(f"Database connection error: {e}")
            raise
        
        # JWT Configuration
        self.JWT_SECRET = jwt_secret or str(uuid.uuid4())
        self.JWT_EXPIRATION = jwt_expiration

    def _hash_password(self, password: str) -> bytes:
        """
        Hash password using bcrypt
        
        :param password: Plain text password
        :return: Hashed password
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def _verify_password(self, plain_password: str, hashed_password: bytes) -> bool:
        """
        Verify password against stored hash
        
        :param plain_password: Plain text password
        :param hashed_password: Stored hashed password
        :return: Password verification result
        """
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

    def register_user(self, email: str, password: str, role: str = 'analyst') -> Dict[str, Any]:
        """
        Register a new user
        
        :param email: User's email address
        :param password: User's password
        :param role: User role (default: analyst)
        :return: User registration result
        """
        try:
            # Validate input
            if not email or not password:
                raise ValueError("Email and password are required")
            
            # Check password strength
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            # Hash password
            hashed_password = self._hash_password(password)
            
            # Prepare user document
            user_doc = {
                'user_id': str(uuid.uuid4()),
                'email': email,
                'password': hashed_password,
                'role': role,
                'created_at': datetime.utcnow(),
                'last_login': None,
                'is_active': True
            }
            
            # Insert user
            result = self.users_collection.insert_one(user_doc)
            
            # Remove sensitive information before returning
            user_doc.pop('password')
            return {
                'success': True,
                'user': user_doc
            }
        
        except DuplicateKeyError:
            self.logger.warning(f"Registration attempt with existing email: {email}")
            return {
                'success': False,
                'error': 'Email already registered'
            }
        except Exception as e:
            self.logger.error(f"User registration error: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user and generate JWT token
        
        :param email: User's email
        :param password: User's password
        :return: Authentication result
        """
        try:
            # Find user by email
            user = self.users_collection.find_one({'email': email})
            
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Verify password
            if not self._verify_password(password, user['password']):
                return {
                    'success': False,
                    'error': 'Invalid credentials'
                }
            
            # Generate JWT token
            token_payload = {
                'user_id': user['user_id'],
                'email': user['email'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(seconds=self.JWT_EXPIRATION)
            }
            
            token = jwt.encode(token_payload, self.JWT_SECRET, algorithm='HS256')
            
            # Update last login
            self.users_collection.update_one(
                {'email': email},
                {'$set': {'last_login': datetime.utcnow()}}
            )
            
            return {
                'success': True,
                'token': token,
                'user_id': user['user_id'],
                'role': user['role']
            }
        
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return {
                'success': False,
                'error': str(e)
            }

def main():
    # Example usage
    user_manager = UserManagement()
    
    # Register a user
    registration = user_manager.register_user(
        email='analyst@threathunter.com', 
        password='SecurePass123!'
    )
    print("Registration:", registration)
    
    # Authenticate user
    auth_result = user_manager.authenticate_user(
        email='analyst@threathunter.com', 
        password='SecurePass123!'
    )
    print("Authentication:", auth_result)

if __name__ == '__main__':
    main()