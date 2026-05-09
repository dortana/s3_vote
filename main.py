from crypto.shamir import ShamirService
from crypto.encryption import EncryptionService
from crypto.pvss import PVSS

from reputation.reputation_engine import ReputationEngine
from reputation.threshold import ThresholdManager

from blockchain.blockchain import Blockchain


# Initialize Services

shamir = ShamirService()

encryption = EncryptionService()

rep_engine = ReputationEngine()

threshold_manager = ThresholdManager()

blockchain = Blockchain()


# Generate ElGamal Keys first — PVSS needs the group parameters (p, g)

private_key, public_key = (
    encryption.generate_keys()
)

print("\nElGamal Keys Generated")
print(f"  p (prime):  {str(public_key['p'])[:40]}…")
print(f"  g (gen):    {str(public_key['g'])[:40]}…")
print(f"  y (pubkey): {str(public_key['y'])[:40]}…")


# Init PVSS with ElGamal group so commitments are g^H(share) mod p

pvss = PVSS(
    p=public_key['p'],
    g=public_key['g']
)


# Secret Sharing

secret = "S3VOTEPRIVATEKEY"

shares = shamir.split_secret(
    secret,
    threshold=3,
    total_shares=5
)

print("\nGenerated Shares:\n")

for share in shares:
    print(share)


# PVSS Commitments  (discrete-log: C_i = g^{H(share_i)} mod p)

commitments = pvss.batch_generate_commitments(
    shares
)

print("\nPVSS Commitments (g^H(share) mod p):\n")

for commitment in commitments:
    print(str(commitment)[:60] + "…")


# PVSS Verification

verification = pvss.batch_verify(
    shares,
    commitments
)

print("\nPVSS Verification:\n")

for i, result in enumerate(verification):

    print(
        f"Share {i+1}:",
        "VALID" if result else "INVALID"
    )


# Store PVSS Commitments On Blockchain

blockchain.add_block({
    "event": "pvss_commitments",
    "commitments": commitments
})


# Voting Phase

vote = "YES"

encrypted_vote = encryption.encrypt_vote(
    public_key,
    vote
)

print("\nEncrypted Vote (ElGamal C1, C2):\n")

print(encrypted_vote)


# Store Vote On Blockchain

blockchain.add_block({
    "event": "vote_cast",
    "encrypted_vote": encrypted_vote
})


# Authority Reputation Values

reputations = {
    "Alice": 1.0,
    "Bob": 0.9,
    "Carol": 0.7,
    "Dave": 0.2,
    "Eve": 0.1
}


# Weight Computation

total_r = sum(reputations.values())

weights = {}

for authority, reputation in reputations.items():

    weights[authority] = (
        rep_engine.calculate_weight(
            reputation,
            total_r,
            len(reputations)
        )
    )

print("\nAuthority Weights:\n")

for authority, weight in weights.items():

    print(
        authority,
        "=>",
        round(weight, 3)
    )


# Adaptive Threshold

threshold = threshold_manager.adaptive_threshold(
    3,
    list(reputations.values())
)

print("\nAdaptive Threshold:")

print(round(threshold, 3))


# Reconstruction Coalition

coalition = [
    "Alice",
    "Bob",
    "Carol"
]

coalition_weight = sum([
    weights[a]
    for a in coalition
])

print("\nCoalition Weight:")

print(round(coalition_weight, 3))


# Reconstruction Decision

if coalition_weight >= threshold:

    recovered_secret = shamir.recover_secret(
        shares[:3]
    )

    print("\nReconstruction SUCCESS")

    print("\nRecovered Secret:")

    print(recovered_secret)

    decrypted_vote = encryption.decrypt_vote(
        private_key,
        encrypted_vote
    )

    print("\nDecrypted Vote:")

    print(decrypted_vote)

else:

    print("\nReconstruction FAILED")


# Store Reconstruction Event

blockchain.add_block({
    "event": "reconstruction",
    "coalition": coalition,
    "weight": coalition_weight
})


# Display Blockchain

print("\nBlockchain State:\n")

blockchain.display_chain()
