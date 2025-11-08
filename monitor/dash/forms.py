from django import forms
from .models import Endpoints, TrafficLog


class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints
        fields = ['ip_address', 'mac_address', 'hostname']

class registertraffic(forms.ModelForm):
    class Meta:
        model = TrafficLog
        fields = ['ip_src', 'ip_dst', 'data_in', 'data_out']