VERSION = (0, 3)


def get_version():
    version = '%s.%s' % (VERSION[0], VERSION[1])
#    if VERSION[2]:
#        version = '%s.%s' % (version, VERSION[2])
#    if VERSION[3] != "final":
#        version = '%s%s%s' % (version, VERSION[3], VERSION[4])
    return version

__version__ = get_version()

import logging
FORMAT = "%(asctime)-15s (%(funcName)s) %(levelname)s: %(message)s"
logging.basicConfig(filename='logging.log',level=logging.DEBUG,format=FORMAT)