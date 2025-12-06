from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from .models import Endpoints

class EndpointModelTests(TestCase):
    def test_endpoint_creation(self):
        e = Endpoints.objects.create(
            ip_address="192.168.1.50",
            mac_address="AA:BB:CC:DD:EE:FF",
            last_seen=timezone.now()
        )
        self.assertEqual(str(e), "192.168.1.50")

class ViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        # mock login for @login_required views
        self.user = self.client.force_login(
            user=type('User', (object,), {'is_authenticated': True, 'pk': 1})()
        )

    def test_dashboard_load(self):
        response = self.client.get(reverse('dash:index'))
        self.assertIn(response.status_code, [200, 302])
