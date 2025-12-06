import time
import socket
import threading
from django.core.management.base import BaseCommand
from dash.datafunctions import run_receiver
from dash.models import Endpoints

class Command(BaseCommand):
    help = 'Starts the UDP listener to ingest packets from the root sniffer'

    def handle(self, *args, **options):
        #start the resolver in a new thread
        resolver_thread = threading.Thread(target=self.resolve_ips, daemon = True)
        resolver_thread.start()

        self.stdout.write(self.style.SUCCESS("Starting Traffic Ingestor..."))
        try:
            #run the main loop
            run_receiver()
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("Listener stopped by user"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Listener crashed: {e}"))

    def resolve_ips(self):
        self.stdout.write(self.style.SUCCESS("Starting IP Resolver..."))
        while True:
            #grab some ips that need resolved
            unresolved_ips = Endpoints.objects.filter(resolution__isnull=True)[:10]
            if not unresolved_ips:
                time.sleep(5)
                continue

            for endpoint in unresolved_ips:
                try:
                    #reverse lookup
                    hostname, _, _ = socket.gethostbyaddr(endpoint.ip_address)
                    endpoint.resolution = hostname
                    endpoint.save()

                except socket.herror:
                    #if lookup fails, mark so as to not loop infinitely on
                    endpoint.resolution = "N/A"
                    endpoint.save()

                except Exception as e:
                    self.stderr.write(f"Error resolving {endpoint.ip_address}: {e}")

            time.sleep(1)
