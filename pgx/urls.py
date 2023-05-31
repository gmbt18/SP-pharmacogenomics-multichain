from django.urls import path

from django.conf.urls.static import static
from django.conf import settings

from . import views

urlpatterns = [
    path("", views.index , name="index"),
    path("home/", views.home, name="home"),
    path("login/", views.authenticate_user, name="login"),
    path("logout/", views.logout, name="logout"),
    path("profile/", views.profile, name="profile"),
    path("register/", views.register_user, name="register_user"),
    path("check_join_requests/", views.join_request_view, name="join_request"),
    path("grant_permissions/<str:name>/<str:address>/", views.grant_permissions, name="grant_permissions"),
    path("create_user/", views.create_data_requester, name="create_user"),
    path("upload_data/", views.upload_data, name="upload_data"),
    path("request_view/", views.request_view, name="request_view"),
    path("request_data/", views.request_data, name="request_data"),
    path("data_table/", views.view_data_table, name="data_table"),
    path("patient_request_data/", views.patient_request_view, name="patient_request"),
    path("manage_access", views.manage_access_view, name="manage_access"),
    path("grant_access/<str:requester_address>/<str:data_id>/<str:purpose>", views.grant_data_access, name="grant_access"),
    path("revoke_access/<str:requester_address>/<str:data_id>/<str:purpose>", views.revoke_data_access, name="revoke_access"),
    path("viewtransactions/", views.transaction_view, name="view_trans"),
    path("patient_transactions/", views.patient_transaction_view, name="patient_trans_view"),
    path("requester_transactions/", views.requester_transaction_view, name="requester_trans_view"),
    
]
