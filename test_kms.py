import unittest
from .kms import KeyManager, DictDatasource, NotFoundError

class TestDatasource(unittest.TestCase):
    def test_put(self):
        datasource = DictDatasource()
        self.assertTrue(datasource.put("test_key", "test_value"))

    def test_get(self):
        datasource = DictDatasource()
        self.assertRaises(NotFoundError, datasource.get("test_key"))
        datasource.put("test_key", "test_value")
        self.assertEqual(datasource.get("test_key"), "test_value")

    def test_delete(self):
        datasource = DictDatasource()
        self.assertRaises(KeyError, datasource.delete("test_key"))
        datasource.put("test_key", "test_value")
        self.assertTrue(datasource.delete("test_key"))

class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.datasource = DictDatasource()
        self.key_manager = KeyManager(datasource=self.datasource, fetch=False)

    def test_init(self):
        self.assertTrue(self.key_manager.init())

    def test_encrypt_and_save(self):
        self.assertTrue(self.key_manager.encrypt_and_save("test_key", "test_value"))
        self.assertIsNotNone(self.datasource.get("test_key"))
        self.assertNotEqual(self.datasource.get("test_key"), "test_value")

    def test_get_and_decrypt(self):
        self.key_manager.encrypt_and_save("test_key", "test_value")
        self.assertEqual(self.key_manager.get_and_decrypt("test_key"), "test_value")

    def test_delete(self):
        self.key_manager.encrypt_and_save("test_key", "test_value")
        self.assertTrue(self.key_manager.delete("test_key"))
