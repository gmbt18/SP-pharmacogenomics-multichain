from Savoir import Savoir
import json
import binascii


rpcuser = "multichainrpc"
rpcpasswd = "DLEBEN97YUVnn4psEojR49ZkEESoYBjZANgX4AQMmP28"
rpchost = "127.0.0.1"
rpcport = "6732"
chainname = "mychain"

multichain_api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)

multichain_api.create("stream", "user_credentials", False)
multichain_api.subscribe("user_credentials")
multichain_api.create("stream", "requester_test", False)
multichain_api.subscribe("requester_test")
multichain_api.create("stream", "patients", False)
multichain_api.subscribe("patients")
multichain_api.create("stream", "organizations", False)
multichain_api.subscribe("organizations")
multichain_api.create("stream", "auditors", False)
multichain_api.subscribe("auditors")
multichain_api.create("stream", "request_data", False)
multichain_api.subscribe("request_data")
multichain_api.create("stream", "pgx_data", False)
multichain_api.subscribe("pgx_data")
multichain_api.create("stream", "access_tx", False)
multichain_api.subscribe("access_tx")
multichain_api.create("stream", "org_request", False)
multichain_api.subscribe("org_request")