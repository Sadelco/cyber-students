from tornado.escape import json_decode
from tornado.gen import coroutine
from .base import BaseHandler
from utils.chacha20_encrypt_decrypt import encrypt, generate_key_nonce, hash_password

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
    # Generate a new encryption key and nonce
        key, nonce = generate_key_nonce()

        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            address = body.get('address')
            dob = body.get('dob')
            phonenumber = body.get('phonenumber')
            disabilitylevel = body.get('disabilitylevel')
            # if display_name is None:
            #   display_name = email

            # Hash the user's password for secure storage.
            hashed_password = hash_password(password)
            # Encrypt personal data fields using the generated key and nonce.
            encrypted_display_name = encrypt(display_name, key, nonce)
            encrypted_address = encrypt(address, key, nonce)
            encrypted_dob = encrypt(dob, key, nonce)
            encrypted_phonenumber = encrypt(phonenumber, key, nonce)
            encrypted_disabilitylevel = encrypt(disabilitylevel, key, nonce)

            if not isinstance(display_name, str):
                raise Exception()
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

        if not address:
            self.send_error(400, message='The address is invalid!')
            return

        if not dob:
            self.send_error(400, message='The dob is invalid!')
            return

        if not phonenumber:
            self.send_error(400, message='The phone number is invalid!')
            return

        if not disabilitylevel:
            self.send_error(400, message='The disabilitylevel is invalid!')
            return

        # Check if email is already in use.
        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
        # upload the personal data to mongo DB
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'displayName': encrypted_display_name,
            'address': encrypted_address,
            'dob': encrypted_dob,
            'phonenumber': encrypted_phonenumber,
            'disabilitylevel': encrypted_disabilitylevel,
            'key': key.hex(),  # In a production scenario the key would be stored securely, not in the DB
            'nonce': nonce.hex() # In a production scenario the nounce would be stored securely, not in the DB
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['password'] = hashed_password    # most secure not to show passwords in the clear on JSON responses
        self.response['displayName'] = display_name
        self.response['address'] = address
        self.response['dob'] = dob
        self.response['phonenumber'] = phonenumber
        self.response['disabilitylevel'] = disabilitylevel

        self.write_json()
