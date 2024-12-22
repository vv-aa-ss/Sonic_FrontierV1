import os
import time
from solana.publickey import PublicKey
from solana.keypair import Keypair
from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
import base58
from dotenv import load_dotenv

load_dotenv()

TESTNETv1_URL = 'https://api.testnet.v1.sonic.game'
connection = Client(TESTNETv1_URL)

LAMPORTS_PER_SOL = 1000000000

def sleep(ms):
    time.sleep(ms / 1000.0)

def send_sol(from_keypair, to_public_key, amount):
    transaction = Transaction()
    transaction.add(
        transfer(
            TransferParams(
                from_pubkey=from_keypair.public_key,
                to_pubkey=to_public_key,
                lamports=int(amount * LAMPORTS_PER_SOL)
            )
        )
    )

    try:
        response = connection.send_transaction(transaction, from_keypair, opts=TxOpts(skip_preflight=True))
        print('Transaction confirmed with signature:', response['result'])
    except Exception as e:
        print(f'Error sending transaction: {e}')

def generate_random_addresses(count):
    addresses = []
    for _ in range(count):
        keypair = Keypair.generate()
        addresses.append(str(keypair.public_key))
    return addresses

def get_keypair_from_seed(seed_phrase):
    seed = Bip39SeedGenerator(seed_phrase).Generate()
    bip44 = Bip44.FromSeed(seed, Bip44Coins.SOLANA)
    account = bip44.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
    private_key = account.PrivateKey().Raw().ToBytes()
    return Keypair.from_secret_key(private_key)

def get_keypair_from_private_key(private_key):
    decoded = base58.b58decode(private_key)
    return Keypair.from_secret_key(decoded)

def parse_env_array(env_var):
    try:
        return eval(env_var) if env_var else []
    except Exception as e:
        print(f'Failed to parse environment variable: {env_var}', e)
        return []

def main():
    seed_phrases = parse_env_array(os.getenv('SEED_PHRASES'))
    private_keys = parse_env_array(os.getenv('PRIVATE_KEYS'))

    keypairs = []

    for seed_phrase in seed_phrases:
        keypairs.append(get_keypair_from_seed(seed_phrase))

    for private_key in private_keys:
        keypairs.append(get_keypair_from_private_key(private_key))

    if not keypairs:
        raise ValueError('No valid SEED_PHRASES or PRIVATE_KEYS found in the .env file')

    random_addresses = generate_random_addresses(100)
    print('Generated 100 random addresses:', random_addresses)

    amount_to_send = 0.001
    current_keypair_index = 0

    for address in random_addresses:
        to_public_key = PublicKey(address)
        try:
            send_sol(keypairs[current_keypair_index], to_public_key, amount_to_send)
            print(f'Successfully sent {amount_to_send} SOL to {address}')
        except Exception as error:
            print(f'Failed to send SOL to {address}:', error)

        sleep(3000)

        current_keypair_index = (current_keypair_index + 1) % len(keypairs)

    print("\nDONE\n")

if __name__ == '__main__':
    main()
