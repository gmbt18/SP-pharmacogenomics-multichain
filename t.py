from Savoir import Savoir
import json
import binascii

rpcuser = "multichainrpc"
rpcpasswd = "DLEBEN97YUVnn4psEojR49ZkEESoYBjZANgX4AQMmP28"
rpchost = "127.0.0.1"
rpcport = "6732"
chainname = "mychain"

multichain_api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)

address = "1XgnEWBJCvXLn3KefKmWsFibr4EJTrdJNEHLst"
filtername = "filter.access_control"
approve = {"for": "patient_pgx_data", "approve": True}


multichain_api.approvefrom(address, filtername, approve)
