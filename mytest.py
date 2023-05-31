import hashlib
import secrets
from Savoir import Savoir
import json
import binascii


rpcuser = "multichainrpc"
rpcpasswd = "DLEBEN97YUVnn4psEojR49ZkEESoYBjZANgX4AQMmP28"
rpchost = "127.0.0.1"
rpcport = "6732"
chainname = "mychain"

multichain_api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)


username = "requester1"

# multichain_api.create("stream", "pgx_data", False)
# multichain_api.subscribe("pgx_data")
# Publish the user's credentials and address to the 'user_credentials' stream

# options = "offchain"

# name = "John Doe"
# organization = "AdminOrg"

# user_data =  f"{name}:{organization}"
# user_data_hex = binascii.hexlify(user_data.encode()).decode()

# multichain_api.publish('requester-test', username, user_data_hex, options)


def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


def generate_salt():
    return secrets.token_hex(32)


items = multichain_api.liststreamitems("requester-test")
if items:
    for item in items:
        item = item["data"]
        item = binascii.unhexlify(item).decode()
        # item = json.loads(item)
        # print(item)
address = "13BfwTXgvbMUsTjPq2H3mBwXGHLe57qtDkPsjE"
permissions = ["write"]

key = "168cEUB3Mqe97fRRhAeyMxbXqv3iVPxukc7T9P"

permissions = "user_credentials.write"

username = "burkin01"
password = "passmedat"
addr = key
role = "requester"
options = "offchain"
salt = generate_salt()
password_hash = hash_password(password, salt)
data = f"{salt}:{password_hash}:{addr}:{role}"
data_hex = binascii.hexlify(data.encode()).decode()


items = multichain_api.liststreamitems("org_request")
if items:
    for item in items:
        item = item["data"]
        item = binascii.unhexlify(item).decode()
        # item = json.loads(item)
        #print(item)

name = "auditor1"


data = multichain_api.liststreamkeyitems("user_credentials", 'mercs01')

if data:
    for item in data:
        item = item["data"]
        item = binascii.unhexlify(item).decode()
        # item = json.loads(item)
        #print(item)

stream_items = multichain_api.liststreamitems("request-data", False, 256)

for item in stream_items:
    data_hex = item["data"]
    data_str = binascii.unhexlify(data_hex).decode()
    #add = data_str.split(":")[2]
    print(data_str)
