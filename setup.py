import glob
from setuptools import setup, find_packages

PACKAGE_NAME = 'key-management-python'
PACKAGE_VERSION = "0.01"

if __name__ == '__main__':
    setup(
        name=PACKAGE_NAME,
        version=PACKAGE_VERSION,
        description='Manage keys for application',
        license='Apache License, Version 2.0',
        packages=find_packages(),
        scripts=glob.glob('*.py'),
        install_requires=[
            'pycrypto==2.6.1',
            'google-cloud-datastore==1.1.0',
        ],
        zip_safe=True
    )
