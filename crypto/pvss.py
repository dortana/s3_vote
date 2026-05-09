import hashlib


class PVSS:
    """
    Simplified PVSS using discrete-log commitments over the ElGamal group.

    Commitment: C_i = g^{H(share_i)} mod p
    This ties each share commitment to the same group as the vote encryption,
    consistent with Schoenmakers (1999).
    """

    def __init__(self, p=None, g=None):

        self.p = p
        self.g = g

    def _hash_to_exponent(self, share):

        h = int(hashlib.sha256(share.encode()).hexdigest(), 16)

        if self.p:
            # Reduce into valid exponent range [2, p-2]
            return h % (self.p - 2) + 2

        return h

    def generate_commitment(self, share):

        exponent = self._hash_to_exponent(share)

        if self.p and self.g:
            # Discrete-log commitment: C_i = g^{H(share)} mod p
            return pow(self.g, exponent, self.p)

        # Fallback if no group parameters provided
        return exponent

    def verify_share(self, share, commitment):

        return self.generate_commitment(share) == commitment

    def batch_generate_commitments(self, shares):

        return [
            self.generate_commitment(s)
            for s in shares
        ]

    def batch_verify(self, shares, commitments):

        return [
            self.verify_share(shares[i], commitments[i])
            for i in range(len(shares))
        ]
