from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception("Token not provided")
        except Exception as e:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        # Lookup the user in the database based on the provided token.
        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'address': 1,
            'dob': 1,
            'phonenumber': 1,
            'disabilitylevel': 1,
            'key': 1,       # Encryption key for the session
            'nonce': 1,     # Nonce associated with the encryption key
            'expiresIn': 1  # Expiration time of the token
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        # Check if the current time is greater than the token's expiration time.
        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # If the token is valid and has not expired, set current_user with the user's details.
        self.current_user = {
            'email': user['email'],
            'displayName': user['displayName'],
            'address': user['address'],
            'dob': user['dob'],
            'phonenumber': user['phonenumber'],
            'disabilitylevel': user['disabilitylevel'],
            'key': user['key'],     # Important for decrypting any encrypted fields
            'nonce': user['nonce']  # Important for decrypting any encrypted fields
        }
