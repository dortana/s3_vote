from flask import Flask
from flask import request
from flask import jsonify

from crypto.encryption import EncryptionService
from blockchain.blockchain import Blockchain


app = Flask(__name__)

encryption = EncryptionService()

blockchain = Blockchain()


# Generate election keys

private_key, public_key = (
    encryption.generate_keys()
)


@app.route("/")
def home():

    return jsonify({
        "system": "S3-Vote",
        "status": "running"
    })


@app.route("/vote", methods=["POST"])
def vote():

    data = request.json

    vote_value = data.get("vote")

    encrypted_vote = encryption.encrypt_vote(
        public_key,
        vote_value
    )

    blockchain.add_block({
        "event": "vote_cast",
        "encrypted_vote": str(encrypted_vote)
    })

    return jsonify({
        "status": "vote stored",
        "encrypted_vote": str(encrypted_vote)
    })


@app.route("/chain")
def chain():

    result = []

    for block in blockchain.chain:

        result.append({
            "index": block.index,
            "data": block.data,
            "hash": block.hash
        })

    return jsonify(result)


if __name__ == "__main__":

    app.run(debug=True)