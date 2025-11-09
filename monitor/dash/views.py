from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Endpoints, TrafficLog
from .forms import registerendpoint, uploadpcap
from .datafunctions import parse_pcap

@login_required
def index(request):
    return render(request, "dash/index.html")

@login_required
def endpoints(request):
    if request.method == "POST":
        form = registerendpoint(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("dash:endpoints"))

    else:
        form = registerendpoint()

    endpoint_list = Endpoints.objects.order_by('ip_address')
    output = {'endpoint_list': endpoint_list,
              'form': form}
    return render(request, "dash/endpoints.html", output)

@login_required
def traffic(request):
    form = uploadpcap()
    context = {'form': form}
    return render(request, "dash/traffic.html", context)

@login_required
def traffic_upload(request):
    if request.method == "POST":
        form = uploadpcap(request.POST, request.FILES)
        if form.is_valid():
            known_ip, traffic = parse_pcap(request.FILES['file'])
            if known_ip is None or traffic is None:
                return HttpResponseRedirect(reverse("dash:traffic"))
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

                return HttpResponseRedirect(reverse("dash:endpoints"))
        else:
            context = {'form': form}
            return render(request, "dash/traffic.html", context)
    else:
        form = uploadpcap()
    return render(request, 'dash/traffic.html', {'form': form})

@login_required
def detail(request, ip_address):
    endpoint = get_object_or_404(Endpoints, pk=ip_address)
    traffic = TrafficLog.objects.filter(ip_src=endpoint)
    return render(request, "dash/detail.html", {'endpoint': endpoint, 'traffic': traffic})

@login_required
def communications(request):
    pairs = TrafficLog.objects.all()
    return render(request, "dash/communications.html", {'pairs': pairs})

# @login_required
# def endpoint_register(request):
#     form = registerendpoint()
#     context = {'form': form}
#     return render(request, "dash/endpoint_register.html", context)
#
# @login_required
# def endpoint_submission(request):
#     if request.method == "POST":
#         form = registerendpoint(request.POST)
#         if form.is_valid():
#             form.save()
#             return HttpResponseRedirect(reverse("dash:endpoints"))
#         else:
#             context = {'form': form}
#             return render(request, "dash/endpoint_register.html", context)
#     return HttpResponseRedirect(reverse("dash:endpoint_register"))
#
#
#
