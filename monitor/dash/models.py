from django.db import models


class Endpoints(models.Model):
    ip_address = models.GenericIPAddressField(primary_key=True)
    mac_address = models.CharField(max_length=17)
    hostname = models.CharField(max_length=255)
    last_seen = models.DateTimeField(auto_now=True, auto_now_add=False)

    def __str__(self):
        return self.ip_address

class TrafficLog(models.Model):
    pk = models.CompositePrimaryKey('ip_src', 'ip_dst')
    data_in = models.BigIntegerField(default=0)
    data_out = models.BigIntegerField(default=0)
    interval_start = models.DateTimeField(auto_now=True, auto_now_add=False)
    ip_src = models.ForeignKey(Endpoints, on_delete=models.CASCADE)
    ip_dst = models.GenericIPAddressField()

    def __str__(self):
        return self.pk



