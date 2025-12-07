from django.db import close_old_connections, transaction
from django.db.models import F, Sum, Subquery, OuterRef
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from .models import Endpoints, TrafficLog, VirusTotalLog
from .forms import registerendpoint, uploadpcap, virustotaluploadfile
from .datafunctions import parse_pcap, virustotalupload
import sys, os, subprocess, ipaddress, socket, io, threading
from django.contrib import messages

PCAP_LOCK = os.path.join(settings.BASE_DIR, 'pcap_import.lock')

@login_required
def index(request):
    #get the 5 most recently seen endpoints and the 5 most talkative endpoints
    recent_endpoints = Endpoints.objects.order_by('-last_seen')[:5]
    talkative_endpoints = TrafficLog.objects.annotate(
        total_traffic= F('data_out') + F('data_in')
    ).order_by('-total_traffic')[:5]

    #get the total number of endpoints and the total amount of traffic sent/received across all endpoints
    total_endpoints = Endpoints.objects.count()

    #total traffic for remote connections
    remote_ips = Endpoints.objects.filter(mac_address='Remote').values_list('ip_address', flat=True)
    total_traffic = TrafficLog.objects.filter(ip_dst__in=remote_ips).aggregate(
        total_data_in=Sum('data_in'),
        total_data_out=Sum('data_out'),
    )

    remote_in = total_traffic.get('total_data_in') or 0
    remote_out = total_traffic.get('total_data_out') or 0

    total_remote_traffic = remote_in + remote_out


    #total traffic across all endpoints
    total_traffic_all = TrafficLog.objects.aggregate(
        total_data_in_all=Sum('data_in'),
        total_data_out_all=Sum('data_out'),
    )

    #if database is empty (new db), return 0 instead of None
    total_all_in = total_traffic_all.get('total_data_in_all') or 0
    total_all_out = total_traffic_all.get('total_data_out_all') or 0

    corrected_total_traffic = (total_all_in + total_all_out - total_remote_traffic)/2 + total_remote_traffic


    #context for the webpage
    context = {
        'recent_endpoints': recent_endpoints,
        'talkative_endpoints': talkative_endpoints,
        'total_endpoints': total_endpoints,
        'total_data_in': total_traffic.get('total_data_in', 0),
        'total_data_out': total_traffic.get('total_data_out', 0),
        'total_data_through': corrected_total_traffic,
    }

    return render(request, "dash/index.html", context)

@login_required
def traffic_rate(request):
    #this view is used by the charts for info updates
    remote_ips = Endpoints.objects.filter(mac_address='Remote').values_list('ip_address', flat=True)
    total_traffic = TrafficLog.objects.filter(ip_dst__in=remote_ips).aggregate(
        total_data_in=Sum('data_in'),
        total_data_out=Sum('data_out'),
    )

    total_data_in = total_traffic.get('total_data_in') or 0
    total_data_out = total_traffic.get('total_data_out') or 0

    return JsonResponse({'total_bytes': total_data_out + total_data_in})

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

    #sort endpoints into local and public
    for endpoint in all_endpoints:
        try:
            ip = ipaddress.ip_address(endpoint.ip_address)

            if ip.is_private or ip.is_loopback:
                local_endpoints.append(endpoint)
            else:
                public_endpoints.append(endpoint)

        except ValueError:
            #if the ip is bad, make it 'public'
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
                if response.get('status') == 'error':
                    messages.error(request, response.get('message', 'VirusTotal Error'))

                else:
                    virustotal_result = response
                    messages.success(request, "File uploaded to VirusTotal.")
    else:
        virustotal_form = virustotaluploadfile()

    context = {'pcap_form': pcap_form,
               'virustotal_form': virustotal_form,
               'virustotal_result': virustotal_result}
    return render(request, 'dash/traffic.html', context)

def is_receiver_running():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('127.0.0.1', 9999))
        return False
    except OSError:
        return True
    finally:
        sock.close()

def background_pcap(file):
    close_old_connections()

    try:
        with open(PCAP_LOCK, 'w') as f:
            f.write('locked')
    except OSError:
        print('Error: Could not create lock file.')
        return

    try:
        # the dictionaries from the parsing function
        known_ip, traffic = parse_pcap(file)

        # if the parsing function failed, return to traffic page
        if known_ip is None or traffic is None:
            return HttpResponseRedirect(reverse("dash:traffic"))

        # otherwise, save to the database
        with transaction.atomic():
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

        print('Import successful.')

    except Exception as e:
        print(f'Error: {e}')
    finally:
        if os.path.exists(PCAP_LOCK):
            os.remove(PCAP_LOCK)

        close_old_connections()

#handles uploading the pcap and parsing
@login_required
def traffic_upload(request):
    virustotal_form = virustotaluploadfile()
    receiver_running = is_receiver_running()
    if request.method == "POST":
        if receiver_running:
            messages.error(request, "Traffic Receiver is running; disable before uploading a file.")
            return HttpResponseRedirect(reverse("dash:traffic"))

        pcap_form = uploadpcap(request.POST, request.FILES)
        if pcap_form.is_valid():
            uploaded_file = request.FILES['file']
            file_copy = io.BytesIO(uploaded_file.read())

            thread = threading.Thread(target=background_pcap, args=(file_copy,))
            thread.daemon = True
            thread.start()

            messages.success(request, "File uploaded and processing started in the background.")
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
        #absolute path to manage.py
        manage_path = os.path.join(settings.BASE_DIR, 'manage.py')
        if 'start_receiver' in request.POST:
            if os.path.exists(PCAP_LOCK):
                messages.error(request, "A PCAP is being processed.")

            else:
                try:
                    #spawn a new process to run the traffic receiver
                    subprocess.Popen([sys.executable, manage_path, 'listen_traffic'])
                    messages.success(request, "Traffic Receiver started in the background.")
                except Exception as e:
                    messages.error(request, f"Failed to start receiver: {e}")

        elif 'stop_receiver' in request.POST:
            try:
                #kill the process running the traffic receiver
                subprocess.run(['pkill', '-f', 'manage.py listen_traffic'])
                messages.warning(request, "Traffic Receiver stopped.")
            except Exception as e:
                messages.error(request, f"Failed to stop receiver: {e}")

    return render(request, "dash/monitor.html")

