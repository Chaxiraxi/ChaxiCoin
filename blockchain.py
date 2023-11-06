# A custom blockchain implementation in Python from bitcoin.pdf whitepaper by Satoshi Nakamoto (2008) (https://bitcoin.org/bitcoin.pdf).
# This is not meant to be a bitcoin implementation, but rather a simple proof of concept of how a blockchain works.
from hashlib import sha256
from time import time
from typing import Any, List, Optional, Tuple, Dict
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from uuid import uuid4
import json

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a public-private keypair

    Returns:
        Tuple[bytes, bytes]: Public and private keypair
    """    
    private_key: bytes = RSA.generate(2**10).export_key()
    public_key: bytes = RSA.import_key(private_key).publickey().export_key()
    return public_key, private_key

def sign(private_key: bytes, data: str) -> bytes:
    """Sign a message with a private key

    Args:
        private_key (bytes): Private key
        data (str): Message to be signed

    Returns:
        bytes: Signature
    """    
    privkey: RSA.RsaKey = RSA.import_key(private_key)
    signer: pkcs1_15.PKCS115_SigScheme = pkcs1_15.new(privkey)
    h: SHA256.SHA256Hash = SHA256.new(data.encode())
    return signer.sign(h)

class Transaction:
    def __init__(self: 'Transaction', sender_address: str, recipient_address: str, value: int, sender_private_key: bytes = b"Genesis", time: int = int(time()), txid: str = sha256(str(uuid4()).encode()).hexdigest(), sender_signature: str = ""):
        """Create a transaction

        Args:
            sender_address (str): Address of the sender
            recipient_address (str): Address of the recipient
            value (int): Value of the transaction
            sender_private_key (bytes): Private key of the sender
        """        
        self.sender_pubkey: str = sender_address
        self.recipient_pubkey: str = recipient_address
        self.value: int = value
        self.time: int = time
        self.txid: str = txid
        self.hash = self.calculate_hash()
        self.sender_signature: str = sender_signature
        if sender_private_key == b"Genesis":
            if sender_signature == "":
                self.sender_signature = "Genesis"
            else:
                self.sender_signature = sender_signature
        else:
            self.sender_signature = sign(sender_private_key, self.hash).hex()

    def calculate_hash(self) -> str:
        """Calculate the hash of the transaction

        Returns:
            str: Hash of the transaction
        """        
        data: str = self.sender_pubkey + self.recipient_pubkey + \
            str(self.value) + str(self.time) + self.txid
        return sha256(data.encode()).hexdigest()
    
    def is_valid(self) -> bool:
        """Check if the transaction is valid

        Returns:
            bool: True if the transaction is valid, False otherwise
        """        
        # If sender and recipient are the same, the transaction is valid only if it is a genesis transaction
        if self.sender_pubkey == self.recipient_pubkey:
            if self.sender_signature == "Genesis" and self.sender_pubkey == "Genesis" and self.recipient_pubkey == "Genesis" and self.value == 0:
                return True
            return False
        
        # Recompute the hash of the transaction
        if self.hash != self.calculate_hash():
            return False
        
        # Verify the signature of the transaction
        public_key: RSA.RsaKey = RSA.import_key(bytes.fromhex(self.sender_pubkey))
        verifier: pkcs1_15.PKCS115_SigScheme = pkcs1_15.new(public_key)
        h: SHA256.SHA256Hash = SHA256.new(self.hash.encode())
        try:
            verifier.verify(h, bytes.fromhex(self.sender_signature))
            return True
        except (ValueError, TypeError):
            return False
        
class Block:
    def __init__(self: 'Block', index: int, previous_hash: str, transactions: List[Transaction], miner_address: str, timestamp: int = int(time()), nonce: int = 0):
        """Defines a block in the blockchain

        Args:
            index (int): Block index
            previous_hash (str): Hash of the previous block
            transactions (List[Transaction]): List of transactions
            miner_address (str): Address of the miner
        """        
        self.index: int = index
        self.previous_hash: str = previous_hash
        self.timestamp: int = timestamp
        self.transactions: List[Transaction] = transactions
        self.nonce: int = nonce
        self.miner_public_key: str = miner_address # Used to reward the miner
        self.hash: str = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculates the hash of the block

        Returns:
            str: Hash of the block
        """        
        # Hash of concatenated signatures of all transactions
        transaction_signatures: str = ""
        for transaction in self.transactions:
            transaction_signatures += str(transaction.sender_signature)

        transaction_signatures_hash: str = sha256(
            transaction_signatures.encode()).hexdigest()

        data: str = str(self.index) + str(self.previous_hash) + \
            str(self.timestamp) + \
            str(transaction_signatures_hash) + str(self.miner_public_key) + str(self.nonce)
        return sha256(data.encode()).hexdigest()

    def mine_block(self, difficulty: int = 4):
        """Mines the block

        Args:
            difficulty (int): Difficulty of the mining process
        """
        self.transactions = self.validate_transactions()[0]
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def validate_transactions(self, blockchain: Optional['Blockchain'] = None) -> Tuple[List[Transaction], List[Transaction]]:
        """Validate all the transactions in the block and return valid and invalid transactions

        Returns:
            Tuple[List[Transaction], List[Transaction]]: Valid and invalid transactions
            Blockchain: Blockchain used to validate balances
        """        
        invalid_transactions: List[Transaction] = []
        valid_transactions_txids: List[str] = []
        genesis_transactions: List[Transaction] = []

        for transaction in self.transactions:
            # Check if transactions are individually valid
            if not transaction.is_valid():
                invalid_transactions.append(transaction)
                continue

            # Check if a Genesis transaction is present
            if transaction.sender_pubkey == "Genesis":  # This is a valid Genesis transaction since it has already been validated above
                # Check if this is the Genesis block
                if self.index != 0:
                    # Remove all Genesis transactions (that's not the Genesis block)
                    invalid_transactions.append(transaction)
                    continue

            # Check if there are duplicate transactions
            if transaction.txid in valid_transactions_txids:
                # If the transaction is invalid, it is already in the invalid_transactions list
                if transaction not in invalid_transactions:
                    # If the sender is the same
                    if transaction.sender_pubkey == self.transactions[valid_transactions_txids.index(transaction.txid)].sender_pubkey:
                        # Remove all duplicate transactions (double spending cancellation)
                        invalid_transactions.append(transaction)
            else:
                valid_transactions_txids.append(transaction.txid)

            # Check if the sender has enough balance to make the transaction
            if blockchain is not None:
                sender_balance: int = blockchain.get_balance(transaction.sender_pubkey)
                if sender_balance < transaction.value:
                    invalid_transactions.append(transaction)
                    continue

            # Add Genesis transactions to a separate list
            if transaction.sender_pubkey == "Genesis":
                genesis_transactions.append(transaction)

        # Check if there are multiple valid Genesis transactions. If so, keep the one with the earliest timestamp
        if len(genesis_transactions) > 1:
            # Get the earliest Genesis transaction
            earliest_genesis_transaction: Transaction = genesis_transactions[0]
            for transaction in genesis_transactions:
                if transaction.time < earliest_genesis_transaction.time:
                    earliest_genesis_transaction = transaction

            # Remove all Genesis transactions except the earliest one
            for transaction in genesis_transactions:
                if transaction != earliest_genesis_transaction:
                    invalid_transactions.append(transaction)

        return [transaction for transaction in self.transactions if transaction not in invalid_transactions], invalid_transactions

class Blockchain:
    def __init__(
        self: 'Blockchain',
        difficulty: int = 2,
        mining_reward: int = 10,
        block_list: List[Block] = [Block(-1, "0", [Transaction("Genesis", "Genesis", -10, b"Genesis")], "Genesis")],
        pending_transactions: List[Transaction] = [Transaction("Genesis", "Genesis", 0, b"Genesis")]
    ):
        """Create and initialize the blockchain"""
        self.difficulty: int = difficulty
        self.mining_reward: int = mining_reward
        self.chain: List[Block] = block_list
        self.pending_transactions: List[Transaction] = pending_transactions
        
    def is_block_valid(self, block: Block) -> bool:
        """Check if the new block is valid

        Args:
            block (Block): Block to be checked

        Returns:
            bool: True if the block is valid, False otherwise
        """        
        # Check if the block hash is valid
        if block.hash != block.calculate_hash():
            return False
        
        # Check if previous block hash is valid
        if block.previous_hash != self.get_latest_block().hash:
            return False
        
        # Check if the transactions in the block are valid
        if len(block.validate_transactions(self)[1]) > 0:
            return False
        
        # Check block index
        if block.index != self.get_latest_block().index + 1:
            return False
        
        return True

    def verify_blockchain(self) -> bool:
        """Verify the blockchain

        Returns:
            bool: True if the blockchain is valid, False otherwise
        """        
        for i in range(1, len(self.chain)):
            current_block: Block = self.chain[i]
            previous_block: Block = self.chain[i - 1]

            # Check if the block hash is valid
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Check if previous block hash is valid
            if current_block.previous_hash != previous_block.hash:
                return False
            
            # Check if the transactions in the block are valid
            if len(current_block.validate_transactions(self)[1]) > 0:
                return False
            
            # Check block index
            if current_block.index != previous_block.index + 1:
                return False
            
        return True
    
    def get_latest_block(self) -> Block:
        """Gets the latest block in the chain

        Returns:
            Block: The latest block
        """        
        return self.chain[-1]

    def get_balance(self, address: str) -> int:
        """Get the balance of an address

        Args:
            address (str): Address of the user

        Returns:
            int: Balance of the user
        """        
        balance: int = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender_pubkey == address:
                    balance -= transaction.value
                if transaction.recipient_pubkey == address:
                    balance += transaction.value
            if block.miner_public_key == address:
                balance += self.mining_reward
        return balance
    
    def add_transaction(self, transaction: Transaction):
        """Add a transaction to the blockchain

        Args:
            transaction (Transaction): Transaction to be added
        """        
        self.pending_transactions.append(transaction)

    def add_block(self, block: Block):
        """Add a block to the blockchain

        Args:
            block (Block): Block to be added
        """        
        if self.is_block_valid(block):
            self.chain.append(block)
        else:
            print("Invalid block, not added to the blockchain.")

    def mine_pending_transactions(self, miner_address: str) -> Block:
        """Mine the pending transactions

        Args:
            miner_address (str): Address of the miner

        Returns:
            Block: Mined block
        """        
        block: Block = Block(len(self.chain), self.get_latest_block().hash,
                      self.pending_transactions, miner_address)
        # Backup the pending transactions list in case of a mining cancellation (will further be useful when multithreading will be implemented)
        pending_transactions_backup: List[Transaction] = self.pending_transactions.copy()
        # Reset pending transactions list so new transactions can be added while mining
        self.pending_transactions = []
        block.mine_block(self.difficulty)   # Start in a new thread so new transactions can be added while mining and we can handle a mining cancellation
        return block

        # No need to add a mining reward transaction since it is already included in the block

def serialize_transaction(transaction: Transaction) -> str:
    """Serialize a transaction into a JSON object

    Args:
        transaction (Transaction): Transaction to be serialized

    Returns:
        str: Serialized transaction
    """    
    return json.dumps({"sender_pubkey": transaction.sender_pubkey, "recipient_pubkey": transaction.recipient_pubkey, "value": transaction.value, "time": transaction.time, "txid": transaction.txid, "hash": transaction.hash, "sender_signature": transaction.sender_signature})

def deserialize_transaction(transaction: str) -> Transaction:
    """Deserialize a transaction from a JSON object

    Args:
        transaction (str): Serialized transaction

    Returns:
        Transaction: Deserialized transaction

    Raises:
        ValueError: If the transaction cannot be deserialized
    """    
    try:
        transaction_json: Dict[str, Any] = json.loads(transaction)
        return Transaction(
            sender_address=transaction_json["sender_pubkey"],
            recipient_address=transaction_json["recipient_pubkey"],
            value=transaction_json["value"],
            time=transaction_json["time"],
            txid=transaction_json["txid"],
            sender_signature=transaction_json["sender_signature"]
        )
    except Exception as e:
        raise ValueError("Could not deserialize transaction") from e
    

def serialize_block(block: Block) -> str:
    """Serialize a block into a JSON object

    Args:
        block (Block): Block to be serialized

    Returns:
        str: Serialized block
    """    
    transactions: List[str] = []
    for transaction in block.transactions:
        transactions.append(serialize_transaction(transaction))
    return json.dumps({"index": block.index, "previous_hash": block.previous_hash, "timestamp": block.timestamp, "transactions": transactions, "nonce": block.nonce, "miner_public_key": block.miner_public_key, "hash": block.hash})

def deserialize_block(block: str) -> Block:
    """Deserialize a block from a JSON object

    Args:
        block (str): Serialized block

    Returns:
        Block: Deserialized block
    """
    try:
        block_json: Dict[str, Any] = json.loads(block)
        transactions: List[Transaction] = []
        for transaction in block_json["transactions"]:
            try:
                transactions.append(deserialize_transaction(transaction))
            except Exception as e:
                raise ValueError("Could not deserialize block") from e
            
        return Block(
            index=block_json["index"],
            previous_hash=block_json["previous_hash"],
            timestamp=block_json["timestamp"],
            transactions=transactions,
            nonce=block_json["nonce"],
            miner_address=block_json["miner_public_key"]
        )
    except Exception as e:
        raise ValueError("Could not deserialize block") from e

def serialize_blockchain(blockchain: Blockchain) -> str:
    """Serialize a blockchain into a JSON object

    Args:
        blockchain (Blockchain): Blockchain to be serialized

    Returns:
        str: Serialized blockchain
    """
    blocks: List[str] = []
    for block in blockchain.chain:
        blocks.append(serialize_block(block))
    return json.dumps({"chain": blocks, "difficulty": blockchain.difficulty, "pending_transactions": blockchain.pending_transactions, "mining_reward": blockchain.mining_reward})

def deserialize_blockchain(blockchain: str) -> Blockchain:
    """Deserialize a blockchain from a JSON object

    Args:
        blockchain (str): Serialized blockchain

    Returns:
        Blockchain: Deserialized blockchain
    """
    try:
        blockchain_json: Dict[str, Any] = json.loads(blockchain)
        blocks: List[Block] = []
        for block in blockchain_json["chain"]:
            try:
                blocks.append(deserialize_block(block))
            except Exception as e:
                raise ValueError("Could not deserialize blockchain") from e
            
        return Blockchain(
            difficulty=blockchain_json["difficulty"],
            mining_reward=blockchain_json["mining_reward"],
            block_list=blocks,
            pending_transactions=blockchain_json["pending_transactions"]
        )
    except Exception as e:
        raise ValueError("Could not deserialize blockchain") from e
