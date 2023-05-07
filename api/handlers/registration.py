from json import dumps
from logging import info
import os
from turtle import st
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet  # importing Fernet module

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
                
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')

            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            
            #My Code start
            fullname = body['fullname']
            #excep(fullname)
            if not isinstance(fullname, str):
                raise Exception()
            
            phoneNumber = body['phoneNumber']
            if not isinstance(phoneNumber, str):
                raise Exception()
            
            disabilities = body['disabilities']
            if not isinstance(disabilities, str):
                raise Exception()
            
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            
            dob = body['dob']
            if not isinstance(dob, str):
               raise Exception()
            
            #My Code end
            
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return
        
        #My Code start
        if not fullname:
            self.send_error(400, message='Please provide full name!')
            return
        
        if not phoneNumber:
            self.send_error(400, message='Please provide your phone number!')

        if not disabilities:
            self.send_error(400, message='Please provide provide Y or N and list disabilities if applicable!')
            return
        
        if not address:
            self.send_error(400, message='Please provide your address!')
            return
        
        if not dob:
            self.send_error(400, message='Please provide Your Date of Birth!')
            return

        #My Code stop

        user = yield self.db.users.find_one({
          'email': email
        }, {
            #'password'=1,
            #'salt'=1'
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
        
        # Passphrase hashing
        #salt = user['salt']
        salt = os.urandom(16) # Generating the salt (per user)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1) # Configure the PBKDF (Same for alll user)
        # where we hash the passpharse
        passphrase_bytes = bytes(password, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)
        #print("Hashed passphrase: " + hashed_passphrase.hex())

        # AES Encryption Code
        # Fernet code for encryption
        # Generating a fernet key
        key = b'nFCwEtDJjZbe6R0t3JbRjxltUGpM_LEB3bSxg5Val1M='
        f = Fernet(key)

        # AES Encription Code
        #def aes_ctr_encrypt(a):
         #   '''AES encryption function for PII'''
          #  key = "thebestsecretkeyintheentireworld"
           # key_bytes = bytes(key, "utf-8")
            #nonce_bytes = os.urandom(16)
            #aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
            #aes_ctr_encryptor = aes_ctr_cipher.encryptor()
            
            #plaintext_bytes = bytes(a, "utf-8")
            #ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
            #return ciphertext_bytes.hex()

        yield self.db.users.insert_one({
            'email': email,

            'fullname': f.encrypt(bytes(fullname, "utf-8")),
            'phone number': f.encrypt(bytes(phoneNumber, "utf-8")),
            'address': f.encrypt(bytes(address, "utf-8")),
            'disabilities': f.encrypt(bytes(disabilities, "utf-8")),
            'dob': f.encrypt(bytes(dob, "utf-8")),
            'password': hashed_passphrase,
            'displayName': display_name,
            'salt': salt

            #'fullname': aes_ctr_encrypt(fullname),
            #'phone number': aes_ctr_encrypt(phoneNumber),
            #'address': aes_ctr_encrypt(address),
            #'disabilities': aes_ctr_encrypt(disabilities),
            #'dob': aes_ctr_encrypt(dob),
            #'password': hashed_passphrase.hex(),
            #'displayName': aes_ctr_encrypt(display_name),
            #'displayName': display_name
            #'salt': salt
            
            
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['fullname'] = fullname
        self.response['disabilities'] = disabilities
        self.response['dob'] = dob
        self.response['address'] = address
        self.response['phoneNumber'] = phoneNumber

        self.write_json()