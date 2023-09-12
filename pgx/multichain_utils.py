import binascii
from datetime import datetime
import hashlib
import secrets
from Savoir import Savoir
from django.conf import settings
import json


rpcuser = settings.MULTICHAIN_RPC["rpcuser"]
rpcpasswd = settings.MULTICHAIN_RPC["rpcpasswd"]
rpchost = settings.MULTICHAIN_RPC["rpchost"]
rpcport = settings.MULTICHAIN_RPC["rpcport"]
chainname = settings.MULTICHAIN_RPC["chainname"]

multichain_api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)


def publish_to_stream_with_offchain_data(stream_name, key, hex_data):
    options = "offchain"
    return multichain_api.publish(stream_name, key, hex_data, options)

def get_all_patient_data(stream_name):
    try:
        # get all items from the stream
        stream_items = multichain_api.liststreamitems(stream_name, False, 256)

        patients = []
        for item in stream_items:
            data_hex = item["data"]
            data_str = binascii.unhexlify(data_hex).decode()
            name, address, gene, drugid, iscore, annot, upload = data_str.split(":")
            dataid = f"{address}_{drugid}"
            patient_data = {
                "name": name,
                "address": address,
                "gene": gene,
                "drugid": drugid,
                "iscore": iscore,
                "annot": annot,
                "upload": upload,
                "dataid": dataid,
            }

            patients.append(patient_data)
        return patients
    except Exception as e:
        print(f"Error fetching patients: {str(e)}")
        return None

def grant_perm(address, name):
    multichain_api.grant(address, "activate")
    multichain_api.grant(address, "requester-test.write")
    multichain_api.grant(address, "user_credentials.write")
    multichain_api.grant(address, "pgx_data.write")
    access_data = {
        "org": name,
        "address": address,
        "timestamp": datetime.now().isoformat(),
        "status": "permissions granted",  # or whatever access level is appropriate
    }
    # Convert to hex to publish on the blockchain
    data_hex = binascii.hexlify(json.dumps(access_data).encode()).decode()
    return multichain_api.publish("org_request", address, data_hex)

def grant_requester_perm(address):
    multichain_api.grant(address, "activate")
    return multichain_api.grant(address, "request-data.write")

def grant_patient_perm(address):
    multichain_api.grant(address, "activate")
    
    return multichain_api.grant(address, "access_tx.write")

def get_join_requests(stream_name):
    try:
        # get all items from the stream
        stream_items = multichain_api.liststreamitems(stream_name, False, 256)
        prev_name = ''
        prev_status = ''
        requests = []
        for item in reversed(stream_items):
            data_hex = item["data"]
            address = item["keys"][0]
            data_str = binascii.unhexlify(data_hex).decode()
            data_str = json.loads(data_str)

            name = data_str.get("name", "org")
            status = data_str["status"]
            if (
                status == "No grants yet"
                and prev_status != "permissions granted"
                and prev_status != "No grants yet"
                and name != prev_name
            ):
                request = {
                    "name": name,
                    "address":address,
                    "status": status,
                }
                requests.append(request)

            prev_name = name
            prev_status = status

        return requests
    except Exception as e:
        print(f"Error fetching patients: {str(e)}")
        return None

def get_all_requests(stream_name, patient_address):
    try:
        # get all items from the stream
        stream_items = multichain_api.liststreamkeyitems(stream_name, patient_address)
        requests = []
        for item in reversed(stream_items):
            data_hex = item["data"]
            data_str = binascii.unhexlify(data_hex).decode()
            data_str = json.loads(data_str)
            status = data_str.get("status")
            name = data_str.get("name")
            organization = data_str.get("organization")
            address = data_str.get("requester")
            data_id = data_str.get("data")
            if not data_str.get("purpose"):
                purpose = "Research"
            else:
                purpose = data_str.get("purpose")
            
            if check_grant(organization, data_id) or data_id == '':
                status = 'grant/deny'

            if status == "waitlisted":
                request = {
                    "name": name,
                    "organization": organization,
                    "address": address,
                    "data": data_id,
                    "purpose": purpose,
                    "status": status,
                }
                
                requests.append(request)

        return requests
    except Exception as e:
        print(f"Error fetching patients: {str(e)}")
        return None
    
def get_all_data(address):
    patient_data = multichain_api.liststreamkeyitems('pgx_data', address)
    data_array = []
    for d in patient_data:
        d_hex = d["data"]
        d_str = binascii.unhexlify(d_hex).decode()
        name,address,gene,drug_id,iscore,annot,uploadedby= d_str.split(":") 
        data_dict = {
            "name": name, 
            "address":address,
            "gene":gene,
            "drugid":drug_id,
            "iscore":iscore,
            "annot":annot,
            "uploadedby":uploadedby,
            }
        data_array.append(data_dict)
    return data_array

def check_request(purpose, patient_address):
    request = multichain_api.liststreamkeyitems("request-data", patient_address)
    if request:
        for r in request:
            data = r["data"]
            d_str = binascii.unhexlify(data).decode()
            d = json.loads(d_str)
            p = d.get('purpose')
            if p == purpose:
                return True
    return False

def check_grant(organization, dataid):
    grants = multichain_api.liststreamkeyitems("access_tx", organization)
    if grants:
        for grant in grants:
            grant = grant['data']
            grant = binascii.unhexlify(grant).decode()
            grant = json.loads(grant)
            data = grant.get('data_id')
            if dataid == data:
                return True
        return False
    else: 
        return False
    
def check_deny(organization, purpose):
    access = multichain_api.liststreamkeyitems("access_tx", organization)
    if access:
        for deny in access:
            deny = deny['data']
            deny = binascii.unhexlify(denyu).decode()
            deny = json.loads(deny)
            p = deny.get('purpose')
            status = deny.get('access_level')
            if p == purpose and status == 'deny': 
                return True
        return False
    else: 
        return False
    
def check_address(address):
    stream_items = multichain_api.liststreamitems("user_credentials", False, 256)

    for item in stream_items:
        data_hex = item["data"]
        data_str = binascii.unhexlify(data_hex).decode()
        add = data_str.split(":")[2]
        if add == address:
            return True
        
    return False
def check_name(name):
    stream_items = multichain_api.liststreamitems('patients', False, 256)
    isnamesame = False
    for item in stream_items:
        data_hex = item["data"]
        data_str = binascii.unhexlify(data_hex).decode()
        patient_name= data_str.split(":")[0]
        print(patient_name,name)
        if patient_name == name:
            isnamesame = True
    if isnamesame:
        return True
    else:
        return False

def publish_to_stream_from_address(org, stream_name, key, hex_data):
    options = "offchain"
    return multichain_api.publishfrom(org, stream_name, key, hex_data, options)


def publish_request(requester, stream_name, key, hex_data):
    options = "offchain"
    return multichain_api.publishfrom(requester, stream_name, key, hex_data, options)
    #return multichain_api.publish(stream_name, key, hex_data, options)

def get_all_granted(requester_address):
    req = multichain_api.liststreamkeyitems('requester-test', requester_address)
    req = req[0]['data']
    req = binascii.unhexlify(req).decode()
    org = req.split(":")[1]
    grant = multichain_api.liststreamkeyitems('access_tx', org)
    data_map = {}
    for item in grant:
        grant_data = item["data"]
        data_str = binascii.unhexlify(grant_data).decode()
        data_str = json.loads(data_str)
        status = data_str["access_level"]
        data = data_str["data_id"]
        patient_address = data_str["patient_address"]
        drugid = data.split("_")[1]
        patient_data = multichain_api.liststreamkeyitems('pgx_data', patient_address)
        for d in patient_data:
            d_hex = d["data"]
            d_str = binascii.unhexlify(d_hex).decode()
            name,address,gene,drug_id,iscore,annot,uploadedby= d_str.split(":")
            if drug_id == drugid:
                data_dict = {
                    "name": name, 
                    "address":address,
                    "gene":gene,
                    "drugid":drug_id,
                    "iscore":iscore,
                    "annot":annot,
                    "uploadedby":uploadedby,
                    "status": status
                    }
                if status == "grant":
                    data_map[data] = data_dict
                elif status == "revoke" and data in data_map:
                    del data_map[data]

    p_data = list(data_map.values())
    return p_data     

def getallrequesterswithaccess(patient_address):
    grant = multichain_api.liststreamitems('access_tx', False, 256)
    data_map = {}
    temp = ''
    for item in reversed(grant):
        grant_data = item["data"]
        data_str = binascii.unhexlify(grant_data).decode()
        data_str = json.loads(data_str)
        address = data_str["patient_address"]
        requesters = []
        if address == patient_address:
            status = data_str["access_level"]
            data = data_str["data_id"]
            if not data_str.get("purpose"):
                purpose = "Research"
            else:
                purpose = data_str.get("purpose")
            org = data_str["org"]
            reqorg = multichain_api.liststreamitems('requester-test', False, 256)
            for req in reqorg:
                reqhex = req['data']
                req = binascii.unhexlify(reqhex).decode()
                organization = req.split(':')[1]
                name = req.split(':')[0]
                if organization == org:
                    requesters.append(name)
            if status == "grant" and org!=temp:
                data_dict = {
                    "organization": org,
                    "requesters": requesters,
                    "data": data,
                    "purpose":purpose,
                    "status": status,
                }
                data_map[org] = data_dict
            elif status == "revoke":
                temp = org
    
    access_data = list(data_map.values())
    print(access_data)
    return access_data    

def grant_access(patient_address, org, data_id, purpose):
    # Prepare the data
    access_data = {
        "patient_address": patient_address,
        "org": org,
        "data_id": data_id,
        "purpose": purpose,
        "timestamp": datetime.now().isoformat(),
        "access_level": "grant",  
    }
    json_data = json.dumps(access_data)
    hex_data = json_data.encode().hex()
    return multichain_api.publishfrom(patient_address,"access_tx", org, hex_data)

def deny_access(patient_address, org, data_id, purpose):
    # Prepare the data
    access_data = {
        "patient_address": patient_address,
        "org": org,
        "data_id": data_id,
        "purpose":purpose,
        "timestamp": datetime.now().isoformat(),
        "access_level": "deny",  
    }
    # Convert to hex to publish on the blockchain
    json_data = json.dumps(access_data)
    hex_data = json_data.encode().hex()
    return multichain_api.publishfrom(patient_address,"access_tx", org, hex_data)

def revoke_access(patient_address, org, data_id, purpose):
    # Prepare the data
    access_data = {
        "patient_address": patient_address,
        "org": org,
        "data_id": data_id,
        "purpose":purpose,
        "timestamp": datetime.now().isoformat(),
        "access_level": "revoke",  
    }
    # Convert to hex to publish on the blockchain
    json_data = json.dumps(access_data)
    hex_data = json_data.encode().hex()
    return multichain_api.publishfrom(patient_address,"access_tx", org, hex_data)

def generate_salt():
    return secrets.token_hex(32)

def create_org_address():
    address = multichain_api.getnewaddress()
    permissions = "connect,send,receive"
    multichain_api.grant(address, permissions)
    return address

def create_address():
    address = multichain_api.getnewaddress()
    permissions = "connect"
    multichain_api.grant(address, permissions)
    return address

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def get_user_data(stream_name, key):
    items = multichain_api.liststreamkeyitems(stream_name, key)
    if items:
        items = list(reversed(items))
        data = items[0]["data"]
        return data
    return None

def get_publisher_address(stream_name, key):
    items = multichain_api.liststreamkeyitems(stream_name, key)
    if items:
        publisher = items[0]['publishers'][0]
        return publisher
    return None
def get_status(stream_name, key):
    items = multichain_api.liststreamkeyitems(stream_name, key)
    if items:
        return items
    return None
def get_access_control_tx():
    tx = multichain_api.liststreamitems('access_tx', False, 256)
    datalist = []
    for item in tx:
        txid = item['txid']
        data = item['data']
        data = bytes.fromhex(data).decode('utf-8')
        data = json.loads(data)
        p_address = data['patient_address']
        r_address = data['org']
        dataid = data['data_id']
        if not data.get("purpose"):
            purpose = "Research"
        else:
            purpose = data.get("purpose")
        timestamp = data['timestamp']
        timestamp = datetime.fromisoformat(timestamp)
        timestamp = timestamp.strftime("%B %d, %Y, %H:%M:%S")    
        access_level = data['access_level']
        data_dict = {
            "txid": txid,
            "patient_address": p_address,
            "org": r_address,
            "dataid":dataid,
            "purpose": purpose,
            "timestamp":timestamp,
            "access_level":access_level,
        }
        datalist.append(data_dict)
    return datalist

def get_tx_org(name):
    tx = multichain_api.liststreamkeyitems('access_tx', name)
    print(tx)
    datalist = []
    for item in tx:
        txid = item['txid']
        data = item['data']
        data = bytes.fromhex(data).decode('utf-8')
        data = json.loads(data)
        p_address = data['patient_address']
        dataid = data['data_id']
        timestamp = data['timestamp']
        timestamp = datetime.fromisoformat(timestamp)
        timestamp = timestamp.strftime("%B %d, %Y, %H:%M:%S")    
        access_level = data['access_level']
        if not data.get("purpose"):
            purpose = "Research"
        else:
            purpose = data.get("purpose")
        patient = get_user_data('patients', p_address)
        if not patient:
            patient=get_user_data('patients', 'gab')
        patient_str = binascii.unhexlify(patient).decode()
        name = patient_str.split(':')[0]
        data_dict = {
            "txid": txid,
            "patient_name": name,
            "dataid":dataid,
            "purpose": purpose,
            "timestamp":timestamp,
            "access_level":access_level,
        }
        datalist.append(data_dict)
    return datalist

def get_tx_patient(address):
    tx = multichain_api.liststreamitems('access_tx', False, 256)
    datalist = []
    for item in tx:
        txid = item['txid']
        data = item['data']
        data = bytes.fromhex(data).decode('utf-8')
        data = json.loads(data)
        print(data)
        p_address = data['patient_address']
        org = data['org']
        dataid = data['data_id']
        timestamp = data['timestamp']
        if not data.get("purpose"):
            purpose = "Research"
        else:
            purpose = data.get("purpose")
        timestamp = datetime.fromisoformat(timestamp)
        timestamp = timestamp.strftime("%B %d, %Y, %H:%M:%S")    
        access_level = data['access_level']
        if address == p_address:
            data_dict = {
                "txid": txid,
                "org": org,
                "dataid":dataid,
                "purpose": purpose,
                "timestamp":timestamp,
                "access_level":access_level,
            }
            datalist.append(data_dict)
    return datalist

def org_status(address):
    items = multichain_api.liststreamkeyitems('org_request', address)
    if items:
        items = list(reversed(items))
        data = items[0]["data"]
        data = binascii.unhexlify(data).decode()
        data = json.loads(data)
        status = data['status']
        return status
    return None
