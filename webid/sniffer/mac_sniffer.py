from sqlalchemy import Column, Integer, String, Sequence, Table, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.schema import ForeignKey
from datetime import datetime

from webid.sniffer import Base
import logging
logger = logging.getLogger(name=__name__)


person_devices = Table('person_devices', Base.metadata,
     Column('person_id', Integer, ForeignKey('person.id')),
     Column('device_id', Integer, ForeignKey('device.id'))
 )

class Person(Base):
    __tablename__ = 'person'
    id          = Column(Integer, Sequence('person_id_seq'), primary_key=True)
    uri         = Column(String(255),unique=True)
    devices     = relationship('Device', secondary=person_devices, cascade="all, delete", backref='owners')

    def __init__(self,URI):
        self.uri = URI


class Device(Base):
    __tablename__ = 'device'
    id          = Column(Integer, Sequence('device_id_seq'), primary_key=True)
    uri         = Column(String(255),unique=True)
    mac         = Column(String(20),unique=True)
    first_seen  = Column(DateTime)
    last_seen   = Column(DateTime)

    def __init__(self,MAC,URI=None,FIRST_SEEN=None):
        '''
            initialized the device. First_SEEN value should be seconds
            like time.time()
        '''
        self.uri = URI
        self.mac = MAC
        self.first_seen = datetime.fromtimestamp(FIRST_SEEN)
        self.last_seen = self.first_seen


    def update_last_seen(self,when):
        when =  datetime.fromtimestamp(when)
        if (when - self.last_seen).seconds > 30*60:
            # re-encountered the device
            self.first_seen = when
        #logger.debug("Updating last seen from %s to %s for %s", self.last_seen, when, self.mac)
        self.last_seen = when
