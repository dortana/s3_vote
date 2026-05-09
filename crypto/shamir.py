from shamir_mnemonic import generate_mnemonics
from shamir_mnemonic import combine_mnemonics


class ShamirService:

    def split_secret(
        self,
        secret,
        threshold,
        total_shares
    ):

        secret_bytes = secret.encode()

        # Ensure even byte length
        if len(secret_bytes) % 2 != 0:
            secret_bytes += b'0'

        groups = generate_mnemonics(
            1,
            [(threshold, total_shares)],
            secret_bytes
        )

        return groups[0]

    def recover_secret(self, shares):

        recovered = combine_mnemonics(shares)

        return recovered.decode()