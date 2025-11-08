from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, get_object_or_404, get_list_or_404
from .models import Endpoints, TrafficLog
from .forms import registerendpoint


def index(request):
    return render(request, "dash/index.html")

def endpoints(request):
    endpoint_list = Endpoints.objects.order_by('ip_address')
    output = {'endpoint_list': endpoint_list}
    return render(request, "dash/endpoints.html", output)

def traffic(request):
    return HttpResponse("Hello, world - traffic.")

def detail(request, ip_address):
    endpoint = get_object_or_404(Endpoints, pk=ip_address)
    traffic = get_list_or_404(TrafficLog, ip_src=endpoint)
    return render(request, "dash/detail.html", {'endpoint': endpoint, 'traffic': traffic})

def external_connections(request):
    return render(request, "dash/external.html")

def endpoint_register(request):
    form = registerendpoint()
    context = {'form': form}
    return render(request, "dash/endpoint_register.html", context)

def endpoint_submission(request):
    if request.method == "POST":
        form = registerendpoint(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("dash:endpoints"))
        else:
            context = {'form': form}
            return render(request, "dash/endpoint_register.html", context)
    return HttpResponseRedirect(reverse("dash:endpoint_register"))
