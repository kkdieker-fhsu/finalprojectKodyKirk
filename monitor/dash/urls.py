from django.urls import path

from . import views

app_name = 'dash'

urlpatterns = [
    path("", views.index, name="index"),

    path("endpoints/", views.endpoints, name="endpoints"),

    path("traffic/", views.traffic, name="traffic"),

    path("traffic/upload/", views.traffic_upload, name="traffic_upload"),

    path("endpoints/detail/<str:ip_address>/", views.detail, name="detail"),

    path("endpoints/communications/", views.communications, name="communications"),

    path("traffic/monitor/", views.monitor, name="monitor"),

]
