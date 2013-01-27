from distutils.core import setup, Extension

setup(
    name='python-webid',
    version='0.3',
    author='Ben Carrillo',
    author_email='bennomadic at gmail dot com',
    packages=['webid', 'webid.test'],
    
    download_url='https://github.com/bennomadic/python-webid.git', # OR'https://github.com/yunus/python-webid.git',
    #url='http://pypi.python.org/pypi/TowelStuff/',
    license='LICENSE.txt',
    description='A python lib implementing server-side validation \
    and client ssl authentication following the WebID spec',
    long_description="""A python lib 
    implementing server-side validation and client ssl authentication following the WebID spec.
    Also authorization based on trust connection of the people.
    """,
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
        client certificate, authentication, authorization',
    #dependency_links = ['git://github.com/ametaireau/M2Crypto.git@master#egg=M2Crypto'],
    #tests_require=['pytest'],
    install_requires=[
                      'M2Crypto>=0.20.2', 
                      'rdflib>=3.2.0', 
                      'rdfextras',
                      'requests', 
                      'html5lib'],    
      
    # In fact cbridge is not extension module, rather it embeds python. It will be used by hostapd
    # I put it here to store it in one place.
    ext_modules=[Extension('webid_trust', ['bin/webid_trust.c'], libraries=['python2.7'])]
)