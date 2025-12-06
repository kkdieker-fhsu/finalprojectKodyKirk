from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
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

        User = get_user_model()
        self.user = User.objects.create_user(username='testuser', password='testpassword')

        self.client.force_login(self.user)

    def test_dashboard_load(self):
        response = self.client.get(reverse('dash:index'))
        self.assertIn(response.status_code, [200, 302])