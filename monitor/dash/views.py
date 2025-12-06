from http.client import responses

from django.db.models import F, Sum, Subquery, OuterRef
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Endpoints, TrafficLog, VirusTotalLog
from .forms import registerendpoint, uploadpcap, virustotaluploadfile
from .datafunctions import parse_pcap, virustotalupload
import subprocess
import sys
from django.contrib import messages
import ipaddress

@login_required
def index(request):
    #get the 5 most recently seen endpoints and the 5 most talkative endpoints
    recent_endpoints = Endpoints.objects.order_by('-last_seen')[:5]
    talkative_endpoints = TrafficLog.objects.annotate(
        total_traffic=F('data_in') + F('data_out')
    ).order_by('-total_traffic')[:5]

    #get the total number of endpoints and the total amount of traffic sent/received across all endpoints
    total_endpoints = Endpoints.objects.count()

    remote_ips = Endpoints.objects.filter(mac_address='Remote').values_list('ip_address', flat=True)
    total_traffic = TrafficLog.objects.filter(ip_dst__in=remote_ips).aggregate(
        total_data_in=Sum('data_in'),
        total_data_out=Sum('data_out'),
    )

    total_traffic_all = TrafficLog.objects.aggregate(
        total_data_in_all=Sum('data_in'),
        total_data_out_all=Sum('data_out'),
    )

    #context for the webpage
    context = {
        'recent_endpoints': recent_endpoints,
        'talkative_endpoints': talkative_endpoints,
        'total_endpoints': total_endpoints,
        'total_data_in': total_traffic.get('total_data_in', 0),
        'total_data_out': total_traffic.get('total_data_out', 0),
        'total_data_through': total_traffic_all.get('total_data_in_all', 0) + total_traffic_all.get('total_data_out_all', 0),
    }

    return render(request, "dash/index.html", context)

@login_required
def endpoints(request):
    if request.method == "POST":
        form = registerendpoint(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("dash:endpoints"))

    else:
        form = registerendpoint()

    all_endpoints = Endpoints.objects.order_by('ip_address')

    local_endpoints = []
    public_endpoints = []

    for endpoint in all_endpoints:
        try:
            ip = ipaddress.ip_address(endpoint.ip_address)

            if ip.is_private or ip.is_loopback:
                local_endpoints.append(endpoint)
            else:
                public_endpoints.append(endpoint)

        except ValueError:
            public_endpoints.append(endpoint)

    output = {'local_endpoints': local_endpoints,
              'public_endpoints': public_endpoints,
              'form': form}
    return render(request, "dash/endpoints.html", output)

@login_required
def traffic(request):
    pcap_form = uploadpcap()
    virustotal_form = virustotaluploadfile()
    context = {'pcap_form': pcap_form,
               'virustotal_form': virustotal_form}
    return render(request, "dash/traffic.html", context)

#handles uploading the file to virustotal
@login_required
def virustotal_upload(request):
    pcap_form = uploadpcap()
    virustotal_result = None
    if request.method == "POST":
        virustotal_form = virustotaluploadfile(request.POST, request.FILES)
        if virustotal_form.is_valid():
            response = virustotalupload(request.FILES['file'])
            if response:
                virustotal_result = response
    else:
        virustotal_form = virustotaluploadfile()

    context = {'pcap_form': pcap_form,
               'virustotal_form': virustotal_form,
               'virustotal_result': virustotal_result}
    return render(request, 'dash/traffic.html', context)

#handles uploading the pcap and parsing
@login_required
def traffic_upload(request):
    virustotal_form = virustotaluploadfile()
    if request.method == "POST":
        pcap_form = uploadpcap(request.POST, request.FILES)
        if pcap_form.is_valid():

            #the dictionaries from the parsing function
            known_ip, traffic = parse_pcap(request.FILES['file'])

            #if the parsing function failed, return to traffic page
            if known_ip is None or traffic is None:
                return HttpResponseRedirect(reverse("dash:traffic"))

            #otherwise, save to the database
            else:
                for ip, data in known_ip.items():
                    mac, timestamp = data
                    Endpoints.objects.update_or_create(
                        ip_address=ip,
                        defaults={'mac_address': mac,
                                  'last_seen': timestamp},
                    )

                for traffic_pairs, traffic_data in traffic.items():
                    ip_src, ip_dst = traffic_pairs
                    data_out = traffic_data[0]
                    data_in = traffic_data[1]
                    packets = traffic_data[2]
                    protocol = traffic_data[3]

                    try:
                        ip_src = Endpoints.objects.get(ip_address=ip_src)
                    except:
                        continue
                    TrafficLog.objects.update_or_create(
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        defaults={'data_in': data_in,
                                  'data_out': data_out,
                                  'protocol': protocol,
                                  'total_packets': packets},
                    )

                return HttpResponseRedirect(reverse("dash:communications"))
        else:
            context = {'pcap_form': pcap_form,
                       'virustotal_form': virustotal_form}
            return render(request, "dash/traffic.html", context)
    else:
        form = uploadpcap()

    context = {'pcap_form': uploadpcap(),
               'virustotal_form': virustotal_form}

    return render(request, 'dash/traffic.html', context)

@login_required
def detail(request, ip_address):
    #finds the endpoint in question and any traffic associated with it
    endpoint = get_object_or_404(Endpoints, pk=ip_address)
    traffic = TrafficLog.objects.filter(ip_src=endpoint)
    return render(request, "dash/detail.html", {'endpoint': endpoint, 'traffic': traffic})

@login_required
def communications(request):
    malicious = VirusTotalLog.objects.filter(ip_address_id=OuterRef('ip_dst')).values('malicious')[:1]
    pairs = TrafficLog.objects.select_related('ip_src',
                                              'ip_src__virustotal_log').annotate(dst_malicious=Subquery(malicious)).all()
    return render(request, "dash/communications.html", {'pairs': pairs})

@login_required
def monitor(request):
    if request.method == "POST":
        if 'start_receiver' in request.POST:
            try:
                subprocess.Popen([sys.executable, 'manage.py', 'listen_traffic'])
                messages.success(request, "Traffic Receiver started in the background.")
            except Exception as e:
                messages.error(request, f"Failed to start receiver: {e}")

        elif 'stop_receiver' in request.POST:
            try:
                subprocess.run(['pkill', '-f', 'manage.py listen_traffic'])
                messages.warning(request, "Traffic Receiver stopped.")
            except Exception as e:
                messages.error(request, f"Failed to stop receiver: {e}")

    return render(request, "dash/monitor.html")

