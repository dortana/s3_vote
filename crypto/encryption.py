import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class EncryptionService:

    def generate_keys(self):

        key = RSA.generate(2048)

        private_key = key.export_key()

        public_key = key.publickey().export_key()

        return (
            private_key,
            public_key
        )

    def encrypt_vote(
        self,
        public_key,
        vote
    ):

        rsa_key = RSA.import_key(public_key)

        cipher = PKCS1_OAEP.new(rsa_key)

        encrypted = cipher.encrypt(
            vote.encode()
        )

        return base64.b64encode(
            encrypted
        ).decode()

    def decrypt_vote(
        self,
        private_key,
        encrypted_vote
    ):

        rsa_key = RSA.import_key(private_key)

        cipher = PKCS1_OAEP.new(rsa_key)

        decoded = base64.b64decode(
            encrypted_vote
        )

        decrypted = cipher.decrypt(
            decoded
        )

        return decrypted.decode()