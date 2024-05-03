from tornado.web import authenticated
from .auth import AuthHandler
from utils.chacha20_encrypt_decrypt import decrypt


class UserHandler(AuthHandler):

    @authenticated
    def get(self):

        self.set_status(200)
        try:
            # retrieve encryption key and nonce, These will be needed for encrypting and decrypting data in mongoDB
            key_hex = self.current_user.get('key')
            nonce_hex = self.current_user.get('nonce')

            if not key_hex or not nonce_hex:
            # Properly handle cases where key or nonce is missing and give an error
                raise KeyError("Encryption key or nonce is missing in current user session.")

            # Convert hex string to bytes needed for the decryption process.
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)

            # Use the key and nounce to decrypt personal data from the DB
            decrypted_display_name = decrypt(self.current_user.get('displayName', ''), key, nonce)
            decrypted_address = decrypt(self.current_user.get('address', ''), key, nonce)
            decrypted_dob = decrypt(self.current_user.get('dob', ''), key, nonce)
            decrypted_phonenumber = decrypt(self.current_user.get('phonenumber', ''), key, nonce)
            decrypted_disabilitylevel = decrypt(self.current_user.get('disabilitylevel', ''), key,
                                                nonce) if self.current_user.get('disabilitylevel') else None

            self.response = {
                'email': self.current_user.get('email', ''),
                'displayName': decrypted_display_name,
                'address': decrypted_address,
                'dob': decrypted_dob,
                'phonenumber': decrypted_phonenumber,
                'disabilitylevel': decrypted_disabilitylevel
            }
        except KeyError as e:
            self.send_error(500, message=str(e))
            return
        except Exception as e:
            self.send_error(500, message=f"An error occurred during decryption: {str(e)}")
            return
        self.write_json()