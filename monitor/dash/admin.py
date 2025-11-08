from django.contrib import admin

from .models import Endpoints, TrafficLog

admin.site.register(Endpoints)

#admin.site.register(TrafficLog)