import os
import json

from Crypto.PublicKey import ElGamal
from Crypto.Random import random as rnd


class EncryptionService:

    def generate_keys(self):

        key = ElGamal.generate(512, os.urandom)

        private_key = {
            'p': int(key.p),
            'g': int(key.g),
            'y': int(key.y),
            'x': int(key.x),
        }

        public_key = {
            'p': int(key.p),
            'g': int(key.g),
            'y': int(key.y),
        }

        return private_key, public_key

    def encrypt_vote(self, public_key, vote):

        p = public_key['p']
        g = public_key['g']
        y = public_key['y']

        # Encode vote string as integer (fits in p for short strings)
        m = int.from_bytes(vote.encode(), 'big')

        # ElGamal: C1 = g^k mod p, C2 = m * y^k mod p
        k = rnd.randint(2, p - 2)
        C1 = pow(g, k, p)
        C2 = (m * pow(y, k, p)) % p

        return json.dumps({'C1': C1, 'C2': C2})

    def decrypt_vote(self, private_key, encrypted_vote):

        data = json.loads(encrypted_vote)
        C1 = data['C1']
        C2 = data['C2']

        p = private_key['p']
        x = private_key['x']

        # Recover m = C2 * (C1^x)^-1 mod p
        s = pow(C1, x, p)
        s_inv = pow(s, p - 2, p)   # Fermat's little theorem
        m = (C2 * s_inv) % p

        length = (m.bit_length() + 7) // 8
        return m.to_bytes(length, 'big').decode()
