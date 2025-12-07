import re
from django import forms
from django.core.exceptions import ValidationError
from .models import Endpoints, TrafficLog

#create a datetime widget for use in forms
class DateTimeLocalInput(forms.DateTimeInput):
    input_type = 'datetime-local'

#used in endpoints page to register a new endpoint
class registerendpoint(forms.ModelForm):
    class Meta:
        model = Endpoints

        #the fields to display
        fields = ['ip_address', 'mac_address', 'hostname', 'last_seen', 'resolution']

        #for styling the form
        widgets = {
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'mac_address': forms.TextInput(attrs={'class': 'form-control'}),
            'hostname': forms.TextInput(attrs={'class': 'form-control'}),
            'last_seen': DateTimeLocalInput(attrs={'class': 'form-control'}),
        }

    def clean_mac_address(self):
        mac_address = self.cleaned_data['mac_address'].upper()
        validate_mac_address(mac_address)
        return mac_address

### Feedback from MiniProject 4 - add MAC address validation
def validate_mac_address(value):
    #mac address validation
    if not re.match(r"^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$", value):
        raise ValidationError("Invalid MAC format. Use XX:XX:XX:XX:XX:XX")

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