from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Admin(models.Model):
    name = models.CharField(max_length=255)


class Organization(models.Model):
    name = models.CharField(max_length=255)


class Patient(models.Model):
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    birthdate = models.DateField()
    address = models.TextField(blank=True, null=True)
    contact_info = models.TextField(blank=True, null=True)


class DataRequester(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    profession = models.CharField(max_length=255)
    organization = models.ForeignKey(
        Organization, on_delete=models.SET_NULL, blank=True, null=True
    )
    contact_info = models.TextField(blank=True, null=True)


class PatientData(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    data = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    is_hidden = models.BooleanField(default=False)


class Auditor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    contact_info = models.TextField(blank=True, null=True)


class DataAccessHistory(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    accessed_at = models.DateTimeField(auto_now_add=True)
