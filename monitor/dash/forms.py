from django import forms
from .models import Endpoints

class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints
        fields = ['ip_address', 'mac_address', 'hostname']

