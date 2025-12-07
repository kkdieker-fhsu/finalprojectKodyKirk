### INF601 - Advanced Programming in Python
### Kody Kirk
### Final Project
 
 
# Project Title

Final Project: Packet Monitor

## Description
 
A web application that monitors network traffic in and through a network and tracks endpoints, traffic, 
and protocols. Allows for user registration and login, viewing of traffic pairs, the number of endpoints on 
the network, and registering new ones. Users may also upload PCAP files to populate the database.

## Getting Started
 
### Dependencies
 
Package requirements are in the requirements.txt file. 

```pip install -r requirements.txt```

Additionally, the host this is running on must be Linux and have tshark and tcpdump installed, be running 
iptables/nftables, and have nfnetlink_log enabled. The exact commands will differ based on your environment. For example, 
to install dependencies on Arch:

```sudo pacman -S wireshark-cli tcpdump iptables nftables```

And to enable nflink:

```modprobe nfnetlink_log```

### Installing
 
Before running the webserver, the database must be initialized and an initial superuser created. First, navigate to the 
project's root directory (monitor/) and make the migrations from the models.py file:

```python manage.py makemigrations```

Then, migrate the database:

```python manage.py migrate```

Finally, create a superuser so that the admin interface is available:

```python manage.py createsuperuser```

This project also uses VirusTotal for querying IP addresses. To make use of this, you will need to get an API key of your own 
and add it to datafunctions.py.

Run the following to log packets with iptables/nftables:

```
sudo nft add table arp filter
sudo nft 'add chain arp filter input { type filter hook input priority 0; }'
sudo nft 'add chain arp filter output { type filter hook output priority 0; }'
sudo nft add rule arp filter input log group 1
sudo nft add rule arp filter output log group 1
sudo iptables -I FORWARD 1 -j NFLOG --nflog-group 1
sudo iptables -I OUTPUT 1 -j NFLOG --nflog-group 1
sudo iptables -I INPUT 1 -j NFLOG --nflog-group 1
```

### Executing program
 
With the database initialized and the superuser created, the webserver can be run using:

```python run_server.py```

The sniffer must be run separately as root:

```sudo .venv/bin/python path/to/sniffer.py```

The exact command will differ based on where you placed your virtual environment.
 
## Issues

The webserver should be able to handle any issues that arise. Anything that comes up should output in the console. 
If you are uploading your own PCAP, dpkt does not seem to have a comprehensive protocol library, so some lesser-used protocols may not be 
recognized. This will output to the console as a 'bad packet,' but the rest of the program will continue on. Any 
malformed packets or the like will also be shown as 'bad packet' in the console. 

## Authors
 
Kody Kirk
 
## Version History

* 0.1
    * Initial Release

## Acknowledgments

* [Django](https://docs.djangoproject.com/en/5.2/) for the web framework
* [dpkt](https://kbandla.github.io/dpkt/) for packet parsing
* [Waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/) for WSGI
* [Whitenoise](https://whitenoise.readthedocs.io/en/latest/) for static file middleware
* [VirusTotal](https://docs.virustotal.com/reference/overview) for screening API
* [Requests](https://requests.readthedocs.io/en/latest/) for API calls
* [Wireshark](https://www.wireshark.org/) for sample pcaps (in particular Johannes Weber) and tshark
* [TCPdump](https://www.tcpdump.org/) for packet capture tools
* [Netfilter](https://www.netfilter.org/) for kernel packet management
* [DataTables](https://datatables.net/) for managing tables
* [Bootstrap](https://getbootstrap.com/) for styling
* [jQuery](https://jquery.com/) for DataTables
* [Chart.js](https://www.chartjs.org/) for graphs
* [Gemini](https://gemini.google.com/) for HTML assistance
