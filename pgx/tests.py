from django.test import TestCase, Client
from .multichain_utils import generate_salt, hash_password


class AuthenticationTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_register_and_authenticate(self):
        # Test registration
        response = self.client.post(
            "/register_patient/",
            {
                "username": "testuser",
                "password": "testpassword",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

        # Test authentication with correct password
        response = self.client.post(
            "/authenticate_patient/",
            {
                "username": "testuser",
                "password": "testpassword",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["authenticated"])

        # Test authentication with incorrect password
        response = self.client.post(
            "/authenticate_patient/",
            {
                "username": "testuser",
                "password": "wrongpassword",
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json())
