### INF601 - Advanced Programming in Python
### Kody Kirk
### Mini Project 4
 
 
# Project Title

Mini Project 4: Packet Monitor

## Description
 
A web application that takes in a pcap file and tracks endpoints, traffic, and protocols. Allows for user registration 
and login, viewing of traffic pairs, the number of endpoints on the network, and registering new ones. 

## Getting Started
 
### Dependencies
 
Package requirements are in the requirements.txt file. Requires Django and dpkt. 

```pip install -r requirements.txt```

For the pcap file, you can create your own, or Wireshark provides a number of 
[sample pcaps](https://wiki.wireshark.org/samplecaptures#sample-captures) that I drew from to verify functionality. 
In particular, I used 'The-Ultimate-PCAP.7z' by Johannes Weber. Location of the pcap file does not matter as it gets 
uploaded on the website.

### Installing
 
Before running the webserver, the database must be initialized and an initial superuser created. First, navigate to the 
project's root directory (monitor/) and make the migrations from the models.py file:

```python manage.py makemigrations```

Then, migrate the database:

```python manage.py migrate```

Finally, create a superuser so that the admin interface is available:

```python manage.py createsuperuser```

### Executing program
 
With the database initialized and the superuser created, the webserver can be run using:

```python manage.py runserver```
 
## Issues

The webserver should be able to handle any issues that arise. Anything that comes up should output in the console. 
One known issue is dpkt does not seem to have a comprehensive protocol library, so some lesser-used protocols may not be 
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
* [Wireshark](https://wiki.wireshark.org/samplecaptures#sample-captures) for sample pcaps, in particular Johannes Weber
* [DataTables](https://datatables.net/) for managing tables
* [Bootstrap](https://getbootstrap.com/) for styling
* [jQuery](https://jquery.com/) for DataTables
* [Gemini](https://gemini.google.com/) for HTML assistance
