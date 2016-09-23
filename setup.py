#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

try:
    from setuptools import setup, Extension
except ImportError:
    import ez_setup
    ez_setup.use_setuptools()
    from setuptools import setup, Extension
import os

execfile('./webid/__init__.py')
VERSION = __version__

setup_root = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(setup_root, "src"))

long_description = """A python lib implementing server-side validation and client ssl authentication following the WebID spec"""


setup(
    name='python-webid',
    packages=['webid', 'webid.test','webid.sniffer','webid.utils'],

    include_package_data=True,
    exclude_package_data={
        'requirements': ['%s/*.tar.gz' % VERSION],
    },
    version=VERSION,
    description='A python lib implementing server-side validation \
    and client ssl authentication following the WebID spec',
    long_description=long_description,
    author='Ben Carrillo, yunus durmus',
    author_email='bennomadic at gmail dot com, yunus@yanis.co',
    download_url='https://github.com/bennomadic/python-webid.git',
    #url=...
    dependency_links = ['git://github.com/ametaireau/M2Crypto.git@master#egg=M2Crypto'],
    install_requires=['M2Crypto>=0.20.2', 'rdflib>=4.0', 'rdfextras',
                      'requests', 'html5lib','sqlalchemy','scapy','six'],
    #test_requires=[],
    platforms=['any'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GPL License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='foaf, ssl, webid, x509, certificate, \
        client certificate, authentication',
    tests_require=['pytest'],
    zip_safe=False
)
