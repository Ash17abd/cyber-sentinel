"""Unit tests for Authentication and Password Hashing."""

import unittest
from modules.database import DatabaseManager

class TestAuthentication(unittest.TestCase):

    def test_password_hash_and_verification(self):
        password = "SecureSuperSecretPassword123!"
        pwd_hash, salt = DatabaseManager.hash_password(password)
        self.assertTrue(DatabaseManager.verify_password(password, pwd_hash, salt))
        self.assertFalse(DatabaseManager.verify_password("WrongPassword", pwd_hash, salt))

    def test_default_seed_users(self):
        db = DatabaseManager(":memory:")
        admin = db.authenticate_user("admin", "Admin@12345")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "Admin")

        analyst = db.authenticate_user("analyst", "Analyst@12345")
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst["role"], "Security Analyst")

if __name__ == "__main__":
    unittest.main()
