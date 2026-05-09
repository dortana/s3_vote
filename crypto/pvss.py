import hashlib


class PVSS:

    def generate_commitment(
        self,
        share
    ):

        commitment = hashlib.sha256(
            share.encode()
        ).hexdigest()

        return commitment

    def verify_share(
        self,
        share,
        commitment
    ):

        computed = hashlib.sha256(
            share.encode()
        ).hexdigest()

        return computed == commitment

    def batch_generate_commitments(
        self,
        shares
    ):

        commitments = []

        for share in shares:

            commitments.append(
                self.generate_commitment(share)
            )

        return commitments

    def batch_verify(
        self,
        shares,
        commitments
    ):

        results = []

        for i in range(len(shares)):

            valid = self.verify_share(
                shares[i],
                commitments[i]
            )

            results.append(valid)

        return results