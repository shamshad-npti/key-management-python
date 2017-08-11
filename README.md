[![CircleCI](https://circleci.com/gh/shamshad-npti/key-management-python.svg?style=svg)](https://circleci.com/gh/shamshad-npti/key-management-python)

## Key Management
This module is intended to mitigate security risk associated with storing keys in settings file as a plain text. Using this module sensitive information in an application can be stored to a centralized location in encrypted format and those information such as database password would be retrieved and decrypted when application gets deployed or starts running

### Using KMS

**Command Line**

* Initializing

```bash
$ python -m kms init
```

* Storing a key securely

```bash
# supplying value in command line
$ python -m kms save --name key-name --source 'some-secret-value'

# supplying value from file
$ python -m kms save --name key-name --source "file:///path/to"
```

* Retrieving a key from to secure store

```bash
$ python -m kms get --name key-name
```

* Deleting key from the secure store

```bash
$ python -m kms delete --name key-name
```

**Python Program**

```python
from kms import kms

key_manager = kms.KeyManager()

# initialize key managar
key_manager.init(prompt=False)

# store a secret value to key manager
key_manager.encrypt_and_save(name="key-name", value="some-secret-text")

# retrieve a secret value from key manager
key_manager.get_and_decrypt(name="key-name")

# delete a secret key from key manager
key_manager.delete(name="key-name")
```

**Extending datasource to be used by key manager**

`KeyManager` internally uses `Datasource` (Key Value Datastore) to manage keys.
A new datasource can easily be integrated with `KeyManager` by extending `Datasource` class and supplying an instance of `Datasource` when we create `KeyManager`.

```python
from kms import kms

class MyDatasource(kms.Datasource):
    """
    MyDatasource - extend Datasource
    """
    
    def __init__(self):
        pass

    def get(self, key, key_type=None):
        pass

    def put(self, key, value, key_type=None):
        pass

    def delete(self, key, key_type=None):
        pass

# Now create a KeyManager instance as follow
key_manager = KeyManager(datasource=MyDatasource())
```