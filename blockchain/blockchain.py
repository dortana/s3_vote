import hashlib
import json
import time


class Block:

    def __init__(
        self,
        index,
        data,
        previous_hash
    ):

        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):

        block_string = json.dumps(
            self.__dict__,
            sort_keys=True
        ).encode()

        return hashlib.sha256(
            block_string
        ).hexdigest()


class Blockchain:

    def __init__(self):

        self.chain = [
            self.create_genesis_block()
        ]

    def create_genesis_block(self):

        return Block(
            0,
            "Genesis Block",
            "0"
        )

    def latest_block(self):

        return self.chain[-1]

    def add_block(self, data):

        block = Block(
            len(self.chain),
            data,
            self.latest_block().hash
        )

        self.chain.append(block)

    def display_chain(self):

        for block in self.chain:

            print("\n================")
            print(f"Index: {block.index}")
            print(f"Data: {block.data}")
            print(f"Hash: {block.hash}")
            print("================")