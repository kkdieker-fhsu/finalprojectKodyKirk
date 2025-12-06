from django.db import models

#this table is modifiable in the admin portal, by uploading a pcap, or by adding one in the endpoints page
class Endpoints(models.Model):

    #the ip address
    ip_address = models.GenericIPAddressField(primary_key=True,
                                              verbose_name="IP Address")

    #the mac address
    mac_address = models.CharField(max_length=17,
                                   verbose_name="MAC Address")

    #the hostname
    hostname = models.CharField(max_length=255,
                                null=True,
                                blank=True)
    #the last time the endpoint was seen
    last_seen = models.DateTimeField(null=True,
                                     blank=True,
                                     verbose_name="Last Seen")

    resolution = models.CharField(max_length=255,
                                  null=True,
                                  blank=True)

    #displays the name properly in the admin portal
    class Meta:
        verbose_name_plural = "Endpoints"

    #returns a more human readable output if called in commandline
    def __str__(self):
        return self.ip_address

#this table cannot be registered in the admin portal and is only adjustable manually or by uploading a pcap/sniffing
class TrafficLog(models.Model):
    #the composite primary key; the combination of source and destination is unique, not each individually
    pk = models.CompositePrimaryKey('ip_src',
                                    'ip_dst')

    #the number of bytes coming into the endpoint
    data_in = models.BigIntegerField(default=0)

    #the number of bytes going out of the endpoint
    data_out = models.BigIntegerField(default=0)

    #the source ip; its a foreign key linking to the endpoints table
    ip_src = models.ForeignKey(Endpoints,
                               on_delete=models.CASCADE)

    #the destination ip
    ip_dst = models.GenericIPAddressField()

    #a list of protocols used
    protocol = models.CharField(max_length=256,
                                null=True,
                                blank=True)

    #the total number of packets sent between the source and destination endpoints
    total_packets = models.IntegerField(default=0,
                                        null=True,
                                        blank=True)

    #another output improvement
    def __str__(self):
        return self.pk

class VirusTotalLog(models.Model):
    #link to the endpoints table
    ip_address = models.OneToOneField(
        'Endpoints',
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='virustotal_log'
    )

    #when the scan was performed
    scanned_at = models.DateTimeField(auto_now=True)

    #virustotal stats
    malicious = models.IntegerField(default=0)
    suspicious = models.IntegerField(default=0)
    harmless = models.IntegerField(default=0)
    undetected = models.IntegerField(default=0)

    #country and owner information
    country = models.CharField(max_length=255,
                               null=True,
                               blank=True)
    owner = models.CharField(max_length=255,
                             null=True,
                             blank=True)

    #raw response from the api
    api_response = models.JSONField(null=True,
                                    blank=True)

    #improved output
    def __str__(self):
        return f"{self.ip_address} (Malicious: {self.malicious})"