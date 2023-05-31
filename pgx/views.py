import binascii
import json
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.contrib import messages
from django.shortcuts import redirect, render
from .multichain_utils import *
from .decorators import role_required

from .forms import *

def index(request):
    return redirect('login')

def home(request):
    user = request.session.get('user')
    role = request.session.get('role')

    if user is None or role is None:
        # User is not authenticated, redirect them to the login page
        return redirect('login')
    
    if role == 'admin':
        return redirect('join_request')
    elif role == 'organization':
        return redirect('profile')
    elif role == 'Patient':
        return redirect('patient_request')
    elif role == 'Auditor':
        return redirect('view_trans')
    elif role == 'requester':
        return redirect('request_view')

def register_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password1')
        name = request.POST.get('name')
        role = request.POST.get('role')
        salt = generate_salt()
        password_hash = hash_password(password, salt)

        # Create a new MultiChain address for this user
        address = create_address()

        # Store the username, hashed password, and address together
        data = f"{salt}:{password_hash}:{address}:{role}"
        data_hex = binascii.hexlify(data.encode()).decode()

        # Publish the user's credentials and address to the 'user_credentials' stream
        publish_to_stream_with_offchain_data('user_credentials', username, data_hex)

        # Store the user's name and role on the 'user_profiles' stream
        if role == 'Patient':
            profile_data = f"{name}:{address}"
            profile_data_hex = binascii.hexlify(profile_data.encode()).decode()
            grant_requester_patient(address)
            publish_to_stream_with_offchain_data('patients', address, profile_data_hex)
        elif role == 'Auditor':
            profile_data = f"{name}:{address}"
            profile_data_hex = binascii.hexlify(profile_data.encode()).decode()
            publish_to_stream_with_offchain_data('auditors', address, profile_data_hex)
        elif role == 'organization':
            profile_data = f"{name}:{address}"
            profile_data_hex = binascii.hexlify(profile_data.encode()).decode()
            req_data = {'name':name,'status': 'No grants yet'}
            req_hex = binascii.hexlify(json.dumps(req_data).encode()).decode()
            publish_to_stream_with_offchain_data('organizations', address, profile_data_hex)
            publish_to_stream_with_offchain_data('org_request', address, req_hex)
        
        messages.success(request, "Your account has been successfully registered.")
        return redirect('login')
    return render(request, 'register.html')

def profile(request):
    role = request.session.get('role')
    user = request.session.get('user')
    address = request.session.get('address')
    status = ""
    if role == 'admin':
        user_data = get_user_data('organizations', user)
        if not user_data:
            user_data = get_user_data('organizations', address)
        
        data_str = binascii.unhexlify(user_data).decode()
        name = data_str.split(':')[0]
        context = {'role': role, 'status': status, 'name': name, 'address': address}
    elif role == 'organization':
        user_data = get_user_data('organizations', user)
        if not user_data:
            user_data = get_user_data('organizations', address)
        orgrequest = get_user_data('org_request', address)
        status_hex = binascii.unhexlify(orgrequest).decode()
        status_hex = json.loads(status_hex)
        status = status_hex['status']

        data_str = binascii.unhexlify(user_data).decode()
        name = data_str.split(':')[0]

        context = {'role': role, 'status': status, 'name': name, 'address': address}
    elif role == 'Patient':
        user_data = get_user_data('patients', user)
        if not user_data:
            user_data = get_user_data('patients', address)
        data_str = binascii.unhexlify(user_data).decode()
        name = data_str.split(':')[0]

        context = {'role': role, 'status': status, 'name': name, 'address': address}
    elif role == 'Auditor':
        user_data = get_user_data('auditors', user)
        if not user_data:
            user_data = get_user_data('auditors', address)
        data_str = binascii.unhexlify(user_data).decode()
        name = data_str.split(':')[0]

        context = {'role': role, 'status': status, 'name': name, 'address': address}
    elif role == 'requester':
        user_data = get_user_data('requester-test', user)
        if not user_data:
            user_data = get_user_data('requester-test', address)
        data_str = binascii.unhexlify(user_data).decode()
        name = data_str.split(':')[0]
        organization = data_str.split(':')[1]
        context = {'role': role, 'status': status, 'name': name, 'address': address, 'organization': organization}

    return render(request,'profile.html', context)

@role_required('admin')
def join_request_view(request):
    role = request.session.get('role')
    address = request.session.get('address')
    status = ""
    requests = get_join_requests('org_request')
    return render(request, 'org_request.html', {'requests':requests, "role":role, 'status': status, 'address':address})

@role_required('admin')
def grant_permissions(request, name, address):
    if request.method == 'POST':
        try:
            grant_perm(address, name)
            messages.success(request, f"Permissions have been granted to {address}")
            return redirect('join_request')
        except Exception as e:
            messages.error(request, str(e))
            return redirect('join_request')
    else:
        messages.error(request, "Invalid request")
        return redirect('join_request')

@role_required('admin', 'organization')
def create_data_requester(request): 
    role = request.session.get('role')
    user = request.session.get('user')
    orgadd = request.session.get('address')
    status = ""
    if role == "organization":
        status = org_status(orgadd)
    if role == "admin":
        user_data = get_user_data('organizations', user)
    else:
        user_data = get_user_data('organizations', orgadd)
    org = ""
    if user is None:
        return redirect('login')
    if user_data:
        if role == "admin":
            org = binascii.unhexlify(user_data).decode()
        else:
            org = binascii.unhexlify(user_data).decode()
            org = org.split(':')[0]
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password1')
        name = request.POST.get('name')
        organization = org
        role = "requester"
        salt = generate_salt()
        password_hash = hash_password(password, salt)

        # Create a new MultiChain address for this user
        address = create_address()

        # Store the username, hashed password, and address together
        data = f"{salt}:{password_hash}:{address}:{role}"
        data_hex = binascii.hexlify(data.encode()).decode()

        profile_data = f"{name}:{organization}:{address}"
        profile_data_hex = binascii.hexlify(profile_data.encode()).decode()

        grant_requester_perm(address)

        publish_to_stream_from_address(orgadd,'requester-test', address, profile_data_hex)


        # Publish the user's credentials and address to the 'user_credentials' stream
        publish_to_stream_from_address(orgadd,'user_credentials', username, data_hex)

        messages.success(request, f"User with address {address} has been created.")
        return redirect('create_user')

    return render(request, 'createrequester.html', {"role":role, 'status': status})

def authenticate_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        data_hex = get_user_data('user_credentials', username)
        if data_hex:
            data_str = binascii.unhexlify(data_hex).decode()
            stored_salt, stored_password_hash, address, role = data_str.split(':')
            password_hash = hash_password(password, stored_salt)

            if stored_password_hash == password_hash:
                request.session['user'] = username
                request.session['role'] = role
                request.session['address'] = address
                # Redirect user to home page
                messages.success(request, "You are now logged in as " + str(address))
                return HttpResponseRedirect(reverse('home')) # replace 'home' with the name of your home view
            else:
                messages.error(request,"Invalid password!")
                return redirect('login')
        else:
            messages.error(request,"Username not found!")
            return redirect('login')
   
    return render(request, 'login.html')

@role_required('admin', 'organization')
def upload_data(request):
    role = request.session.get('role')
    user = request.session.get('user')
    orgadd = request.session.get('address')
    status = ""
    if role == "organization":
        status = org_status(orgadd)
    org = get_user_data('organizations', user)
    if org:
        org = binascii.unhexlify(org).decode()
    if request.method == 'POST':
        name = request.POST.get('name')
        address = request.POST.get('address')
        gene = request.POST.get('gene')
        drugid = request.POST.get('drug')
        iscore = request.POST.get('iscore')
        annot = request.POST.get('annot')
        uploaded_by = org
        if not check_address(address) and not check_name(name):
            messages.error(request, "Address and name not found.")
            return redirect('upload_data')
        elif not check_address(address):
            messages.error(request, "Address not found.")
            return redirect('upload_data')
        elif not check_name(name):
            messages.error(request, "Name not found.")
            return redirect('upload_data')
        else:
            data = f"{name}:{address}:{gene}:{drugid}:{iscore}:{annot}:{uploaded_by}"
            data_hex = binascii.hexlify(data.encode()).decode()
            publish_to_stream_from_address(orgadd,'pgx_data', address, data_hex)
            messages.success(request, f"Patient {address} pgx data was uploaded.")
            return HttpResponseRedirect(reverse('upload_data'))




    return render(request, 'createdata.html', {"role":role, 'status': status})        
@role_required("Patient")
def patient_request_view(request):
    role = request.session.get('role')
    address = request.session.get('address')
    status = ""
    requests = get_all_requests('request-data', address)
    return render(request, 'patient_request_view.html', {'requests':requests, "role":role, 'status': status})

@role_required("Patient")
def manage_access_view(request):
    role = request.session.get('role')
    address = request.session.get('address')
    status = ""
    requesters = getallrequesterswithaccess(address)
    return render(request, 'manage_access.html', {'requesters':requesters, "role":role, 'status': status})
  
@role_required("Patient")
def grant_data_access(request, requester_address, data_id, purpose):
    address = request.session.get('address')
    if request.method == 'POST':
        try:
            grant_access(address,requester_address,data_id, purpose)
            messages.success(request, f"You have granted {requester_address} access to your data.")
            return redirect('patient_request')
        except Exception as e:
            messages.error(request, str(e))
            return redirect('patient_request')
    else:
        messages.error(request, "Invalid Request")
        return redirect('patient_request')
    
@role_required("Patient")    
def revoke_data_access(request, requester_address, data_id, purpose):
    address = request.session.get('address')
    if request.method == 'POST':
        try:
            revoke_access(address,requester_address,data_id, purpose)
            messages.success(request, f"You have revoked {requester_address} access to your data.")
            return redirect('patient_request')
        except Exception as e:
            messages.error(request, str(e))
            return redirect('patient_request')
    else:
        messages.error(request, "Invalid Request")
        return redirect('patient_request')
    
@role_required("requester")
def request_view(request):
    status = ""
    role = request.session.get('role')
    address = request.session.get('address')
    patients = get_all_patient_data('pgx_data')
    filtered_patients = patients
    
    select_gene= []
    select_drug= []

    for p in patients:
        gn = p.get('gene')
        dg = p.get('drugid')
        if gn not in select_gene:
            select_gene.append(gn)
        if dg not in select_drug:
            select_drug.append(dg)
    
    gene = request.GET.get('gene_id')
    drug = request.GET.get('drug_id')
    if gene:
        filtered_patients = [t for t in filtered_patients if t.get('gene') == gene]
    if drug:
        filtered_patients = [t for t in filtered_patients if t.get('drugid') == drug]
    patients = filtered_patients
    dat = []
    for patient in patients:
        data = patient['dataid']
        items = get_status('access_control', address)
        if items:
            for item in items:
                item = item['data']
                item = binascii.unhexlify(item).decode()
                item = json.loads(item)
                if item['data_id'] != data:
                    dat.append(data)
        else:
            dat.append(data)
    patient_and_data = list(zip(patients,dat))

    context = {'pd':patient_and_data, "role":role, 'status': status, 'drugs':select_drug, 'genes':select_gene}
    return render(request, 'request_view.html', context)


@role_required("requester")
def request_data(request):
    user = request.session.get('user')
    address = request.session.get('address')
    user_data = get_user_data('requester-test',user)
    if not user_data:
        user_data = get_user_data('requester-test',address)
    data_str = binascii.unhexlify(user_data).decode()
    name, org, add= data_str.split(':')
    if request.method == 'POST':
        purpose = request.POST.get('purpose')
        data_list = request.POST.getlist('selected_patients')
        for data in data_list:
            
            if data != '':
          
                patient_address, data_id = data.split('|')
                if check_request(address, patient_address):
                    messages.error(request, f"You have already requested for {data_id}")
                    continue
                req_data = {'name':name, 'organization':org,'requester':address,'data':data_id, 'purpose':purpose,'status': 'waitlisted'}
                data_hex = binascii.hexlify(json.dumps(req_data).encode()).decode()
            
                publish_request(address, 'request-data', patient_address, data_hex)
        messages.success(request, f"Your request/s has/have been sent")
        return redirect('request_view')
             
    else:
        messages.error(request, "Invalid request")
        return redirect('request_view')
    
@role_required("requester")
def view_data_table(request):
    status = ""
    role = request.session.get('role')
    data = get_all_granted(request.session.get("address"))
    return render(request, "data_table.html", {'data':data, "role":role, 'status': status}) 

@role_required("Auditor")
def transaction_view(request):
    status = ""
    transactions = get_access_control_tx()
    role = request.session.get('role')
    transactions = transactions[::-1]
    select_patient= []
    select_requester= []
    select_access = []
    for t in transactions:
        patient = t.get('patient_address')
        requester = t.get('requester_address')
        access = t.get('access_level')
        if patient not in select_patient:
            select_patient.append(patient)
        if requester not in select_requester:
            select_requester.append(requester)
        if access not in select_access:
            select_access.append(access)
    filtered_transactions = transactions
    patient_address = request.GET.get('patient_address')
    requester_address = request.GET.get('requester_address')
    access_level = request.GET.get('access_level')
    if patient_address:
        filtered_transactions = [t for t in filtered_transactions if t.get('patient_address') == patient_address]
    if requester_address:
        filtered_transactions = [t for t in filtered_transactions if t.get('requester_address') == requester_address]
    if access_level:
        filtered_transactions = [t for t in filtered_transactions if t.get('access_level') == access_level]
        
    context = {
        'transactions':filtered_transactions, 
        "role":role, 
        'status': status, 
        'patients':select_patient, 
        'requesters':select_requester, 
        'access':select_access,
        }    
    return render(request, 'transactions.html', context)

@role_required("Patient")
def patient_transaction_view(request):
    status = ""
    address = request.session.get('address')
    transactions = get_tx_patient(address)
    role = request.session.get('role')
    transactions = transactions[::-1]
    select_requester= []
    select_access = []
    select_org = []
    for t in transactions:
        requester = t.get('name')
        access = t.get('access_level')
        org = t.get('org')
        if requester not in select_requester:
            select_requester.append(requester)
        if access not in select_access:
            select_access.append(access)
        if org not in select_org:
            select_org.append(org)

    filtered_transactions = transactions
    requester_name = request.GET.get('name')
    access_level = request.GET.get('access_level')
    organization = request.GET.get('org')
    if requester_name:
        filtered_transactions = [t for t in filtered_transactions if t.get('name') == requester_name]
    if organization:
        filtered_transactions = [t for t in filtered_transactions if t.get('org') == organization]
    if access_level:
        filtered_transactions = [t for t in filtered_transactions if t.get('access_level') == access_level]
        
    context = {
        'transactions':filtered_transactions, 
        "role":role, 
        'status': status, 
        'names':select_requester, 
        'access':select_access,
        'orgs':select_org,
        }   
    return render(request, 'transactions_patient.html', context)

@role_required("requester")
def requester_transaction_view(request):
    status = ""
    address = request.session.get('address')
    transactions = get_tx_requester(address)
    role = request.session.get('role')
    transactions = transactions[::-1]
    select_patient= []
    select_access = []
    for t in transactions:
        patient = t.get('patient_name')
        access = t.get('access_level')
        if patient not in select_patient:
            select_patient.append(patient)
        if access not in select_access:
            select_access.append(access)
    filtered_transactions = transactions
    patient_name = request.GET.get('patient_name')
    access_level = request.GET.get('access_level')
    if patient_name:
        filtered_transactions = [t for t in filtered_transactions if t.get('patient_name') == patient_name]
    if access_level:
        filtered_transactions = [t for t in filtered_transactions if t.get('access_level') == access_level]
        
    context = {
        'transactions':filtered_transactions, 
        "role":role, 
        'status': status, 
        'patients':select_patient, 
        'access':select_access,
        }
    return render(request, 'transactions_requester.html', context)

def logout(request):
    request.session.flush()  # This will delete all current session data
    return redirect('login')  # Redirect to the login page

