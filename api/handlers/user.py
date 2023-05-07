from tornado.web import authenticated

from .auth import AuthHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet  # importing Fernet module
class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        # Put Decrytion code here to decrypt the data before displaying 
        # Generating a fernet key
        key = b'nFCwEtDJjZbe6R0t3JbRjxltUGpM_LEB3bSxg5Val1M='
        f = Fernet(key)

        
        
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        self.response['phone number'] = f.decrypt(self.current_user['phoneNumber']).decode()
        self.response['address'] = f.decrypt(self.current_user['address']).decode()
        self.response['dob'] = f.decrypt(self.current_user['dob']).decode()
        self.response['disabilities'] = f.decrypt(self.current_user['disabilities']).decode()
        self.write_json()
