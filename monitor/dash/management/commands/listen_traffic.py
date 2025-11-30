from django.core.management.base import BaseCommand
from dash.datafunctions import run_receiver

class Command(BaseCommand):
    help = 'Starts the UDP listener to ingest packets from the root sniffer'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting Traffic Ingestor..."))
        try:
            run_receiver()
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("Listener stopped by user"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Listener crashed: {e}"))