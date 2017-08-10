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