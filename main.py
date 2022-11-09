from __future__ import annotations
import os





prv = ("")

















































FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL",
    # "https://tap.devnet.prod.gcp.aptosdev.com",
    "https://faucet.testnet.aptoslabs.com",
)  # <:!:section_1

# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

import time
from random import choice
from typing import Any, Dict, List, Optional

import httpx


U64_MAX = 18446744073709551615




# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest

# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

import hashlib


import typing
# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

"""
This is a simple BCS serializer and deserializer. Learn more at https://github.com/diem/bcs
"""


import io
import typing
import unittest

MAX_U8 = 2**8 - 1
MAX_U16 = 2**16 - 1
MAX_U32 = 2**32 - 1
MAX_U64 = 2**64 - 1
MAX_U128 = 2**128 - 1


# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0


import unittest

from nacl.signing import SigningKey, VerifyKey
max_gas = 9000
price_gas = 100


# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

"""
This translates Aptos transactions to and from BCS for signing and submitting to the REST API.
"""


import hashlib
import typing
import unittest
from typing import List


# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

from threading import *
from loguru import logger

import typing













class AccountAddress:
    address: bytes
    LENGTH: int = 32

    def __init__(self, address: bytes):
        self.address = address

        if len(address) != AccountAddress.LENGTH:
            raise Exception("Expected address of length 32")

    def __eq__(self, other: AccountAddress) -> bool:
        return self.address == other.address

    def __str__(self):
        return self.hex()

    def hex(self) -> str:
        return f"0x{self.address.hex()}"

    def from_hex(address: str) -> AccountAddress:
        addr = address

        if address[0:2] == "0x":
            addr = address[2:]

        if len(addr) < AccountAddress.LENGTH * 2:
            pad = "0" * (AccountAddress.LENGTH * 2 - len(addr))
            addr = pad + addr

        return AccountAddress(bytes.fromhex(addr))

    def from_key(key: PublicKey) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(key.key.encode() + b"\x00")
        return AccountAddress(hasher.digest())

    def deserialize(deserializer: Deserializer) -> AccountAddress:
        return AccountAddress(deserializer.fixed_bytes(AccountAddress.LENGTH))

    def serialize(self, serializer: Serializer):
        serializer.fixed_bytes(self.address)




class PrivateKey:
    LENGTH: int = 32

    key: SigningKey

    def __init__(self, key: SigningKey):
        self.key = key

    def __eq__(self, other: PrivateKey):
        return self.key == other.key

    def __str__(self):
        return self.hex()

    def from_hex(value: str) -> PrivateKey:
        if value[0:2] == "0x":
            value = value[2:]
        return PrivateKey(SigningKey(bytes.fromhex(value)))

    def hex(self) -> str:
        return f"0x{self.key.encode().hex()}"

    def public_key(self) -> PublicKey:
        return PublicKey(self.key.verify_key)

    def random() -> PrivateKey:
        return PrivateKey(SigningKey.generate())

    def sign(self, data: bytes) -> Signature:
        return Signature(self.key.sign(data).signature)

    def deserialize(deserializer: Deserializer) -> PrivateKey:
        key = deserializer.bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")

        return PrivateKey(SigningKey(key))

    def serialize(self, serializer: Serializer):
        serializer.bytes(self.key.encode())


class PublicKey:
    LENGTH: int = 32

    key: VerifyKey

    def __init__(self, key: VerifyKey):
        self.key = key

    def __eq__(self, other: PrivateKey):
        return self.key == other.key

    def __str__(self) -> str:
        return f"0x{self.key.encode().hex()}"

    def verify(self, data: bytes, signature: Signature) -> bool:
        try:
            self.key.verify(data, signature.data())
        except:
            return False
        return True

    def deserialize(deserializer: Deserializer) -> PublicKey:
        key = deserializer.bytes()
        if len(key) != PublicKey.LENGTH:
            raise Exception("Length mismatch")

        return PublicKey(VerifyKey(key))

    def serialize(self, serializer: Serializer):
        serializer.bytes(self.key.encode())


class Signature:
    LENGTH: int = 64

    signature: bytes

    def __init__(self, signature: bytes):
        self.signature = signature

    def __eq__(self, other: PrivateKey):
        return self.signature == other.signature

    def __str__(self) -> str:
        return f"0x{self.signature.hex()}"

    def data(self) -> bytes:
        return self.signature

    def deserialize(deserializer: Deserializer) -> Signature:
        signature = deserializer.bytes()
        if len(signature) != Signature.LENGTH:
            raise Exception("Length mismatch")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        serializer.bytes(self.signature)


class Test(unittest.TestCase):
    def test_sign_and_verify(self):
        in_value = b"test_message"

        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        signature = private_key.sign(in_value)
        self.assertTrue(public_key.verify(in_value, signature))

    def test_private_key_serialization(self):
        private_key = PrivateKey.random()
        ser = Serializer()

        private_key.serialize(ser)
        ser_private_key = PrivateKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(private_key, ser_private_key)

    def test_public_key_serialization(self):
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        ser = Serializer()
        public_key.serialize(ser)
        ser_public_key = PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(public_key, ser_public_key)

    def test_signature_key_serialization(self):
        private_key = PrivateKey.random()
        in_value = b"another_message"
        signature = private_key.sign(in_value)

        ser = Serializer()
        signature.serialize(ser)
        ser_signature = Signature.deserialize(Deserializer(ser.output()))
        self.assertEqual(signature, ser_signature)




class Account:
    """Represents an account as well as the private, public key-pair for the Aptos blockchain."""

    account_address: AccountAddress
    private_key: PrivateKey
    global w

    def __init__(
            self, account_address: AccountAddress, private_key: PrivateKey
    ):
        self.account_address = account_address
        self.private_key = private_key

    def __eq__(self, other: Account) -> bool:
        return (
                self.account_address == other.account_address
                and self.private_key == other.private_key
        )

    def generate() -> Account:
        private_key = PrivateKey.random()
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)

    def load_my_account() -> Account:
        private_key = PrivateKey.from_hex(
            '')
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)

    def my() -> Account:
        private_key = PrivateKey.from_hex(
            f'{prv}')
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)


    def load_key(key: str) -> Account:
        private_key = PrivateKey.from_hex(key)
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)

    def load(path: str) -> Account:
        with open(path) as file:
            data = json.load(file)
        return Account(
            AccountAddress.from_hex(data["account_address"]),
            PrivateKey.from_hex(data["private_key"]),
        )

    def store(self, path: str):
        data = {
            "account_address": self.account_address.hex(),
            "private_key": self.private_key.hex(),
        }
        with open(path, "w") as file:
            json.dump(data, file)

    def address(self) -> AccountAddress:
        """Returns the address associated with the given account"""

        return self.account_address

    def auth_key(self) -> str:
        """Returns the auth_key for the associated account"""

        return AccountAddress.from_key(self.private_key.public_key()).hex()

    def sign(self, data: bytes) -> Signature:
        return self.private_key.sign(data)

    def public_key(self) -> PublicKey:
        """Returns the public key for the associated account"""

        return self.private_key.public_key()


class RestClient:
    """A wrapper around the Aptos-core Rest API"""

    chain_id: int
    client: httpx.Client
    base_url: str

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client()
        self.chain_id = int(self.info()["chain_id"])

    def close(self):
        self.client.close()

    #
    # Account accessors
    #

    def account(self, account_address: AccountAddress) -> Dict[str, str]:
        """Returns the sequence number and authentication key for an account"""

        response = self.client.get(f"{self.base_url}/accounts/{account_address}")
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    def account_balance(self, account_address: str) -> int:
        """Returns the test coin balance associated with the account"""
        return self.account_resource(
            account_address, "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        )["data"]["coin"]["value"]

    def account_sequence_number(self, account_address: AccountAddress) -> int:
        account_res = self.account(account_address)
        return int(account_res["sequence_number"])

    def account_resource(
            self, account_address: AccountAddress, resource_type: str
    ) -> Optional[Dict[str, Any]]:
        response = self.client.get(
            f"{self.base_url}/accounts/{account_address}/resource/{resource_type}"
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    def get_table_item(
            self, handle: str, key_type: str, value_type: str, key: Any
    ) -> Any:
        response = self.client.post(
            f"{self.base_url}/tables/{handle}/item",
            json={
                "key_type": key_type,
                "value_type": value_type,
                "key": key,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    #
    # Ledger accessors
    #

    def info(self) -> Dict[str, str]:
        response = self.client.get(self.base_url)
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    #
    # Transactions
    #

    def submit_bcs_transaction(self, signed_transaction: SignedTransaction) -> str:
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        response = self.client.post(
            f"{self.base_url}/transactions",
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]

    def submit_transaction(self, sender: Account, payload: Dict[str, Any]) -> str:
        """
        1) Generates a transaction request
        2) submits that to produce a raw transaction
        3) signs the raw transaction
        4) submits the signed transaction
        """

        txn_request = {
            "sender": f"{sender.address()}",
            "sequence_number": str(self.account_sequence_number(sender.address())),
            "max_gas_amount": f"{max_gas}",
            "gas_unit_price": f"{price_gas}",
            "expiration_timestamp_secs": str(int(time.time()) + 600),
            "payload": payload,
        }

        response = self.client.post(
            f"{self.base_url}/transactions/encode_submission", json=txn_request
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        to_sign = bytes.fromhex(response.json()[2:])
        signature = sender.sign(to_sign)
        txn_request["signature"] = {
            "type": "ed25519_signature",
            "public_key": f"{sender.public_key()}",
            "signature": f"{signature}",
        }

        headers = {"Content-Type": "application/json"}
        response = self.client.post(
            f"{self.base_url}/transactions", headers=headers, json=txn_request
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]

    def transaction_pending(self, txn_hash: str) -> bool:
        response = self.client.get(f"{self.base_url}/transactions/by_hash/{txn_hash}")
        if response.status_code == 404:
            return True
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["type"] == "pending_transaction"

    def wait_for_transaction(self, txn_hash: str) -> None:
        """Waits up to 20 seconds for a transaction to move past pending state."""

        count = 0
        while self.transaction_pending(txn_hash):
            assert count < 20, f"transaction {txn_hash} timed out"
            time.sleep(1)
            count += 1
        response = self.client.get(f"{self.base_url}/transactions/by_hash/{txn_hash}")
        assert (
                "success" in response.json() and response.json()["success"]
        ), f"{response.text} - {txn_hash}"

    #
    # Transaction helpers
    #

    def create_multi_agent_bcs_transaction(
            self,
            sender: Account,
            secondary_accounts: List[Account],
            payload: TransactionPayload,
    ) -> SignedTransaction:
        raw_transaction = MultiAgentRawTransaction(
            RawTransaction(
                sender.address(),
                self.account_sequence_number(sender.address()),
                payload,
                100_000,
                100,
                int(time.time()) + 600,
                self.chain_id,
            ),
            [x.address() for x in secondary_accounts],
        )

        keyed_txn = raw_transaction.keyed()

        authenticator = Authenticator(
            MultiAgentAuthenticator(
                Authenticator(
                    Ed25519Authenticator(sender.public_key(), sender.sign(keyed_txn))
                ),
                [
                    (
                        x.address(),
                        Authenticator(
                            Ed25519Authenticator(x.public_key(), x.sign(keyed_txn))
                        ),
                    )
                    for x in secondary_accounts
                ],
            )
        )

        return SignedTransaction(raw_transaction.inner(), authenticator)

    def create_single_signer_bcs_transaction(
            self, sender: Account, payload: TransactionPayload
    ) -> SignedTransaction:
        raw_transaction = RawTransaction(
            sender.address(),
            self.account_sequence_number(sender.address()),
            payload,
            100_000,
            100,
            int(time.time()) + 600,
            self.chain_id,
        )

        signature = sender.sign(raw_transaction.keyed())
        authenticator = Authenticator(
            Ed25519Authenticator(sender.public_key(), signature)
        )
        return SignedTransaction(raw_transaction, authenticator)

    #
    # Transaction wrappers
    def get_number(self):
        number = "".join([choice("0123456789") for _ in range(5)])

        return number


    def multi_send(self, sender: Account, wu: w):
        payload = {
            "function": f"0x1::aptos_account::transfer",
            "type_arguments": [],
            "arguments": [
                f"{wu}",
                "1500000"

            ],
            "type": f"entry_function_payload"
        }
        return self.submit_transaction(sender, payload)




    def mint1(self, sender: Account, number: int) -> str:
        payload = {
            "function": "0x3::token::create_collection_script",
            "type_arguments": [],
            "arguments": [
                f"Martian Testnet{number}",
                "Martian Testnet NFT",
                "https://aptos.dev",
                "9007199254740991",
                [
                    False,
                    False,
                    False
                ]
            ],

            "type": "entry_function_payload",

        }

        return self.submit_transaction(sender, payload)





    def mint(self, sender: Account,  number: int) -> str:
        payload = {
                "function": "0x3::token::create_token_script",
                "type_arguments": [],
                "arguments": [
                    f"Martian Testnet{number}",
                    f"Martian NFT #{number}",
                    "OG Martian",
                    "1",
                    "9007199254740991",
                    "https://gateway.pinata.cloud/ipfs/QmXiSJPXJ8mf9LHijv6xFH1AtGef4h8v5VPEKZgjR4nzvM",
                    "0x57c7a3a39d277b198e7acab1cef6ab3081004c17336887d548d64340d491dbff",
                    "0",
                    "0",
                    [
                        False,
                        False,
                        False,
                        False,
                        False
                    ],
                    [],
                    [],
                    []
                ],
            "type": "entry_function_payload"
        }
        return self.submit_transaction(sender, payload)


    def transfer(self, sender: Account, recipient: AccountAddress, amount: int) -> str:
        """Transfer a given coin amount from a given Account to the recipient's account address.
        Returns the sequence number of the transaction used to transfer."""

        payload = {
            "type": "entry_function_payload",
            "function": "0x1::coin::transfer",
            "type_arguments": ["0x1::aptos_coin::AptosCoin"],
            "arguments": [
                f"{recipient}",
                str(amount),
            ],
        }
        return self.submit_transaction(sender, payload)

    #:!:>bcs_transfer
    def bcs_transfer(
            self, sender: Account, recipient: AccountAddress, amount: int
    ) -> str:
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            transaction_arguments,
        )

        signed_transaction = self.create_single_signer_bcs_transaction(
            sender, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)

    # <:!:bcs_transfer

    #
    # Token transaction wrappers
    #

    #:!:>create_collection
    def create_collection(
            self, account: Account, name: str, description: str, uri: str
    ) -> str:  # <:!:create_collection
        """Creates a new collection within the specified account"""

        transaction_arguments = [
            TransactionArgument(name, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(U64_MAX, Serializer.u64),
            TransactionArgument(
                [False, False, False], Serializer.sequence_serializer(Serializer.bool)
            ),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "create_collection_script",
            [],
            transaction_arguments,
        )

        signed_transaction = self.create_single_signer_bcs_transaction(
            account, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)

    #:!:>create_token
    def create_token(
            self,
            account: Account,
            collection_name: str,
            name: str,
            description: str,
            supply: int,
            uri: str,
            royalty_points_per_million: int,
    ) -> str:  # <:!:create_token
        transaction_arguments = [
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(name, Serializer.str),
            TransactionArgument(description, Serializer.str),
            TransactionArgument(supply, Serializer.u64),
            TransactionArgument(supply, Serializer.u64),
            TransactionArgument(uri, Serializer.str),
            TransactionArgument(account.address(), Serializer.struct),
            # SDK assumes per million
            TransactionArgument(1000000, Serializer.u64),
            TransactionArgument(royalty_points_per_million, Serializer.u64),
            TransactionArgument(
                [False, False, False, False, False],
                Serializer.sequence_serializer(Serializer.bool),
            ),
            TransactionArgument([], Serializer.sequence_serializer(Serializer.str)),
            TransactionArgument([], Serializer.sequence_serializer(Serializer.bytes)),
            TransactionArgument([], Serializer.sequence_serializer(Serializer.str)),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "create_token_script",
            [],
            transaction_arguments,
        )
        signed_transaction = self.create_single_signer_bcs_transaction(
            account, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)

    def offer_token(
            self,
            account: Account,
            receiver: str,
            creator: str,
            collection_name: str,
            token_name: str,
            property_version: int,
            amount: int,
    ) -> str:
        transaction_arguments = [
            TransactionArgument(receiver, Serializer.struct),
            TransactionArgument(creator, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token_transfers",
            "offer_script",
            [],
            transaction_arguments,
        )
        signed_transaction = self.create_single_signer_bcs_transaction(
            account, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)

    def claim_token(
            self,
            account: Account,
            sender: str,
            creator: str,
            collection_name: str,
            token_name: str,
            property_version: int,
    ) -> str:
        transaction_arguments = [
            TransactionArgument(sender, Serializer.struct),
            TransactionArgument(creator, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token_transfers",
            "claim_script",
            [],
            transaction_arguments,
        )
        signed_transaction = self.create_single_signer_bcs_transaction(
            account, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)

    def direct_transfer_token(
            self,
            sender: Account,
            receiver: Account,
            creators_address: AccountAddress,
            collection_name: str,
            token_name: str,
            property_version: int,
            amount: int,
    ) -> str:
        transaction_arguments = [
            TransactionArgument(creators_address, Serializer.struct),
            TransactionArgument(collection_name, Serializer.str),
            TransactionArgument(token_name, Serializer.str),
            TransactionArgument(property_version, Serializer.u64),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "direct_transfer_script",
            [],
            transaction_arguments,
        )

        signed_transaction = self.create_multi_agent_bcs_transaction(
            sender,
            [receiver],
            TransactionPayload(payload),
        )
        return self.submit_bcs_transaction(signed_transaction)

    #
    # Token accessors
    #

    def get_token(
            self,
            owner: AccountAddress,
            creator: AccountAddress,
            collection_name: str,
            token_name: str,
            property_version: int,
    ) -> Any:
        token_store_handle = self.account_resource(owner, "0x3::token::TokenStore")[
            "data"
        ]["tokens"]["handle"]

        token_id = {
            "token_data_id": {
                "creator": creator.hex(),
                "collection": collection_name,
                "name": token_name,
            },
            "property_version": str(property_version),
        }

        try:
            return self.get_table_item(
                token_store_handle,
                "0x3::token::TokenId",
                "0x3::token::Token",
                token_id,
            )
        except ApiError as e:
            if e.status_code == 404:
                return {
                    "id": token_id,
                    "amount": "0",
                }
            raise

    def get_token_balance(
            self,
            owner: AccountAddress,
            creator: AccountAddress,
            collection_name: str,
            token_name: str,
            property_version: int,
    ) -> str:
        return self.get_token(
            owner, creator, collection_name, token_name, property_version
        )["amount"]

    #:!:>read_token_data_table
    def get_token_data(
            self,
            creator: AccountAddress,
            collection_name: str,
            token_name: str,
            property_version: int,
    ) -> Any:
        token_data_handle = self.account_resource(creator, "0x3::token::Collections")[
            "data"
        ]["token_data"]["handle"]

        token_data_id = {
            "creator": creator.hex(),
            "collection": collection_name,
            "name": token_name,
        }

        return self.get_table_item(
            token_data_handle,
            "0x3::token::TokenDataId",
            "0x3::token::TokenData",
            token_data_id,
        )  # <:!:read_token_data_table

    def get_collection(self, creator: AccountAddress, collection_name: str) -> Any:
        token_data = self.account_resource(creator, "0x3::token::Collections")["data"][
            "collection_data"
        ]["handle"]

        return self.get_table_item(
            token_data,
            "0x1::string::String",
            "0x3::token::CollectionData",
            collection_name,
        )

    #
    # Package publishing
    #

    def publish_package(
            self, sender: Account, package_metadata: bytes, modules: List[bytes]
    ) -> str:
        transaction_arguments = [
            TransactionArgument(package_metadata, Serializer.bytes),
            TransactionArgument(
                modules, Serializer.sequence_serializer(Serializer.bytes)
            ),
        ]

        payload = EntryFunction.natural(
            "0x1::code",
            "publish_package_txn",
            [],
            transaction_arguments,
        )

        signed_transaction = self.create_single_signer_bcs_transaction(
            sender, TransactionPayload(payload)
        )
        return self.submit_bcs_transaction(signed_transaction)









from loguru import logger
NODE_URL = os.getenv("APTOS_NODE_URL", "https://fullnode.testnet.aptoslabs.com/v1")
y = 0
if __name__ == "__main__":
    rest_client = RestClient(NODE_URL)
    alice = Account.my()
    while True:
        logger.info("=== Generation Account ===")
        try:
            bob = Account.generate()
        except:
            logger.info("Account generation error")
            break
        logger.info(f"New account generation: Adress: {bob.address()}")
        logger.info("=== Initial transfer ===")
        try:
            txn_hash = rest_client.multi_send(alice, bob.address())
            rest_client.wait_for_transaction(txn_hash)
        except:
            logger.info("Error sending tokens")
        logger.info(f"Main balance:  {rest_client.account_balance(alice.address())}")
        logger.info(f"New account #{y} balance :  {rest_client.account_balance(bob.address())}")
        t = 1
        i = 1
        logger.info("=== Initial mint ===")
        while True:
            try:
                number = rest_client.get_number()
                txn_hash = rest_client.mint1(bob, number)
                rest_client.wait_for_transaction(txn_hash)
                txn_hash = rest_client.mint(bob, number)
                rest_client.wait_for_transaction(txn_hash)
                logger.info(f"Account #{y} mint Martian NFT #{number}")
                i = i + 1
                with open('privatkey.txt', 'a') as file:
                    file.write(f'{bob.private_key}\n')
                y = y + 1
                time.sleep(0.2)
                print("\n")
                print("\n")
                break
            except Exception as ex:
                logger.info(f"Error sending transaction #{t}, {ex}")
                t = t + 1
                time.sleep(10)