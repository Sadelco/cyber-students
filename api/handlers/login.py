from datetime import datetime, timedelta
from time import mktime
from utils.chacha20_encrypt_decrypt import hash_password
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        # Update the user's record in the database with the new token and expiration time.
        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            if not (email and password):
                raise ValueError("Email and password cannot be empty")
        except Exception as e:
            self.send_error(400, message='Invalid input data!')
            return

        user = yield self.db.users.find_one({'email': email})
        if not user:
            self.send_error(403, message='No account found with that email.')
            return

        # Hash the input password to compare with the stored hash.
        hashed_input_password = hash_password(password)

        if user['password'] != hashed_input_password:
            self.send_error(403, message='Incorrect password!')
            return

        # Generate a token for the session if login is successful.
        token = yield self.generate_token(email)

        # Respond with the generated token and its expiration time.
        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()