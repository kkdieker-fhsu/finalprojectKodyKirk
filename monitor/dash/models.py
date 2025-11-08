from django.db import models


class Endpoints(models.Model):
    ip_address = models.GenericIPAddressField(primary_key=True)
    mac_address = models.CharField(max_length=17)
    hostname = models.CharField(max_length=255)
    last_seen = models.DateTimeField(auto_now=True, auto_now_add=False)

class TrafficLog(models.Model):
    indata = models.BigIntegerField()
    outdata = models.BigIntegerField()
    interval_start = models.DateTimeField(auto_now=True, auto_now_add=False)
    endpoint = models.ForeignKey(Endpoints, on_delete=models.CASCADE)