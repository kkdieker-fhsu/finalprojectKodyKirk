from django.db import models


class Endpoints(models.Model):
    ip_address = models.GenericIPAddressField(primary_key=True,
                                              verbose_name="IP Address")
    mac_address = models.CharField(max_length=17,
                                   verbose_name="MAC Address")
    hostname = models.CharField(max_length=255,
                                null=True,
                                blank=True)
    last_seen = models.DateTimeField(null=True,
                                     blank=True,
                                     verbose_name="Last Seen")

    class Meta:
        verbose_name_plural = "Endpoints"

    def __str__(self):
        return self.ip_address

class TrafficLog(models.Model):
    pk = models.CompositePrimaryKey('ip_src', 'ip_dst')
    data_in = models.BigIntegerField(default=0)
    data_out = models.BigIntegerField(default=0)
    ip_src = models.ForeignKey(Endpoints, on_delete=models.CASCADE)
    ip_dst = models.GenericIPAddressField()
    protocol = models.CharField(max_length=256, null=True, blank=True)
    total_packets = models.IntegerField(default=0, null=True, blank=True)

    def __str__(self):
        return self.pk
