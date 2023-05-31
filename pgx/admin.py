from django.contrib import admin
from .models import Patient, Admin

# Register your models here.
admin.site.register(Patient)
admin.site.register(Admin)
