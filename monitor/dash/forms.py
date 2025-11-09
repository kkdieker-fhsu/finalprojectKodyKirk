from django import forms
from .models import Endpoints, TrafficLog

class DateTimeLocalInput(forms.DateTimeInput):
    input_type = 'datetime-local'

class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints
        fields = ['ip_address', 'mac_address', 'hostname', 'last_seen']

        widgets = {
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'mac_address': forms.TextInput(attrs={'class': 'form-control'}),
            'hostname': forms.TextInput(attrs={'class': 'form-control'}),
            'last_seen': DateTimeLocalInput(attrs={'class': 'form-control'}),
        }

class uploadpcap(forms.Form):
    file = forms.FileField()

