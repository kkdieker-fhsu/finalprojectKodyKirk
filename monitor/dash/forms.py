from django import forms
from .models import Endpoints, TrafficLog

#create a datetime widget for use in forms
class DateTimeLocalInput(forms.DateTimeInput):
    input_type = 'datetime-local'

#used in endpoints page to register a new endpoint
class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints

        #the fields to display
        fields = ['ip_address', 'mac_address', 'hostname', 'last_seen']

        #for styling the form
        widgets = {
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'mac_address': forms.TextInput(attrs={'class': 'form-control'}),
            'hostname': forms.TextInput(attrs={'class': 'form-control'}),
            'last_seen': DateTimeLocalInput(attrs={'class': 'form-control'}),
        }

class uploadpcap(forms.Form):
    #upload the pcap
    file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )

class virustotaluploadfile(forms.Form):
    # upload a file for scanning
    file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )