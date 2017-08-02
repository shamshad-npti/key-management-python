"""
Manage key securely
"""
import argparse
import re
import random
import string
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from google.cloud import datastore


class NotFoundError(Exception):
    """
    Key not found execption
    """
    def __init__(self, key):
        super(NotFoundError, self).__init__("key {} not found".format(key))


class KeyType(object):
    rsa_public_key = "rsa_public_key"
    rsa_private_key = "rsa_private_key"
    aes_secret_key = "aes_secret_key"


class Datasource(object):
    def __init__(self):
        pass

    def get(self, key, key_type=None):
        pass

    def put(self, key, value, key_type=None):
        pass

    def delete(self, key, key_type=None):
        pass

class DatastoreDatasource(Datasource):
    namespace = "kms"
    field = "_field"

    def __init__(self, project=None):
        super(DatastoreDatasource, self).__init__()
        self._client = datastore.Client(project=project)

    def _create_key(self, path, namespace=None):
        namespace = namespace or self.namespace
        return self._client.key(self.namespace, path, namespace=namespace)

    def get(self, key, key_type=None):
        data = self._client.get(self._create_key(key))
        if data is None:
            raise NotFoundError(key)
        return data.get(self.field, None)

    def put(self, key, value, key_type=None):
        entity = datastore.Entity(key=key, exclude_from_indexes=(self.field,))
        entity.update({self.field: value})
        self._client.put(entity)
        return True

    def delete(self, key, key_type=None):
        self._client.delete(self._create_key(key))
        return True


class DictDatasource(Datasource):
    def __init__(self):
        super(DictDatasource, self).__init__()
        self.kv_store = dict()

    def get(self, key, key_type=None):
        value = self.kv_store.get(key, None)
        if value is None:
            raise NotFoundError(key)
        return value

    def put(self, key, value, key_type=None):
        self.kv_store[key] = value
        return True

    def delete(self, key, key_type=None):
        del self.kv_store[key]
        return True


class KeyManager(object):
    """
    Manage all keys
    """
    public_key_id = "publicKeyId"
    private_key_id = "privateKeyId"
    secret_key = "secretKey"
    field = "_field"
    num_bits = 1024
    block_size = 32

    def __init__(self, datasource=None, fetch=True):
        """
        fetch the public and private keys from datastore and
        initialize it
        """
        if datasource is None:
            self._datasource = DatastoreDatasource()
        else:
            self._datasource = datasource

        if fetch:
            self._public_key = RSA.importKey(datasource.get(self.public_key_id))
            self._private_key = RSA.importKey(datasource.get(self.private_key_id))
            self._secret_key = self._private_key.decrypt(datasource.get(self.secret_key))

    def _pad(self, value):
        pad = (self.block_size - len(value) % self.block_size)
        return value + pad * chr(pad)

    @staticmethod
    def _unpad(value):
        return value[:-ord(value[-1])]

    def encrypt(self, value):
        """
        encrypt public key
        """
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self._secret_key, AES.MODE_CBC, init_vector)
        return base64.b64encode(init_vector + cipher.encrypt(self._pad(value)))

    def encrypt_and_save(self, name, value):
        """
        encrypt the key value and save it to
        cloud datastore
        """
        return self._datasource.put(name, self.encrypt(value))

    def get(self, name):
        """
        return value stored in datastore
        """
        return self._datasource.get(name)

    def decrypt(self, value):
        """
        decrypt the value
        """
        value = base64.b64decode(value)
        init_vector = value[:AES.block_size]
        cipher = AES.new(self._secret_key, AES.MODE_CBC, init_vector)
        return self._unpad(cipher.decrypt(value[AES.block_size:]).decode("utf-8"))

    def get_and_decrypt(self, name):
        """
        return decrypted key
        """
        return self.decrypt(self.get(name))

    def delete(self, name):
        """
        remove key from storage
        """
        self._datasource.delete(name)
        return True

    def init(self, filename=None, passphrase=None):
        """
        initialize key manager
        """
        if isinstance(filename, basestring):
            rsa_key = RSA.importKey(open(filename, "rb").readlines(), passphrase=passphrase)
            if not rsa_key.has_private():
                raise ValueError("Private is missing")
        else:
            rsa_key = RSA.generate(self.num_bits, Random.new().read)

        chars = string.ascii_letters + string.digits + "!@#$~`.,}{[]()"
        password_plain_text = ''.join([random.choice(chars) for _ in range(15)])
        password_hash = hashlib.sha256(password_plain_text).digest()
        password_encrypted = rsa_key.publickey().encrypt(password_hash, 0)[0]

        self._datasource.put(
            key=self.private_key_id,
            value=rsa_key.exportKey(),
            key_type=KeyType.rsa_private_key
        )
        self._datasource.put(
            key=self.public_key_id,
            value=rsa_key.publickey().exportKey(),
            key_type=KeyType.rsa_public_key
        )
        self._datasource.put(
            key=self.secret_key,
            value=password_encrypted,
            key_type=KeyType.aes_secret_key
        )

        return True


def _save(args):
    regex = re.compile("^file://", re.I)
    if regex.search(args.source):
        data = "\n".join([l[:-1] for l in open(args.source[len("file://"):], "rb").readlines()])
    else:
        data = args.source
    KeyManager().encrypt_and_save(args.name, data)

def _get(args):
    key_manager = KeyManager()
    try:
        key = key_manager.get_and_decrypt(args.name)
        print "*" * 50
        print key
        print "*" * 50
    except NotFoundError as ex:
        raise ex

def _delete(args):
    key_manager = KeyManager()
    key_manager.delete(args.name)

def _init(*args):
    key_manager = KeyManager(fetch=False)
    key_manager.init()

def _main():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest="command")

    save = subparser.add_parser("save")
    save.add_argument("--name", "-n", help="Name of the key")
    save.add_argument("--source", help="source of data")

    get = subparser.add_parser("get")
    get.add_argument("--name", "-n", help="Name of the key")

    delete = subparser.add_parser("delete")
    delete.add_argument("--name", "-n", help="Name of the key")

    subparser.add_parser("init")

    func = {
        "save": _save,
        "get": _get,
        "delete": _delete,
        "init": _init
    }

    args = parser.parse_args()

    func[args.command](args)


def dict_config(config):
    """
    initilize key manager with dictionary configuration
    """
    for key, value in config.iteritems():
        setattr(KeyManager, key, value)

if __name__ == '__main__':
    _main()
