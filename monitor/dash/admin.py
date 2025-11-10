from django.contrib import admin

from .datafunctions import mac_addr
from .models import Endpoints, TrafficLog

#due to using a composite primary key, this table cannot be registered in admin
#admin.site.register(TrafficLog)

class NetworkAdmin(admin.ModelAdmin):
    fieldsets = [
        ('Network Information', {'fields': ['ip_address', 'mac_address', 'hostname'], 'classes': ['collapse']}),
        ('Date Information', {'fields': ['last_seen'], 'classes': ['collapse']})
    ]
    list_display = ('ip_address', 'mac_address', 'hostname', 'last_seen')
    list_filter = ['last_seen']
    search_fields = ['ip_address', 'mac_address', 'hostname']

admin.site.register(Endpoints, NetworkAdmin)
