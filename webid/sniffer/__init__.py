from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

import sqlalchemy.orm.exc

# For the time being hard coded database file. 
# Later on we can put the below lines in a function and then call it to initiate the database 
engine = create_engine('sqlite:///sniff.db', echo=False)
Base = declarative_base(bind=engine)


def createDB_and_session(Sess = sessionmaker()):
    ''' 
        After importing the sniffer and mac_sniffer call this method to create the DB and 
        fetch a session
    '''
    Base.metadata.create_all()
    Sess.configure(bind=engine)
    return Sess()

# Below is supposed to be called from HOSTAPD. We are calling it from C therefore
# initialization is also inside.


import mac_sniffer

session = None
def add_mac_address(mac_address, wheninseconds):
    '''
        mac_address is the mac address as a string
        when is time in seconds (long) since 1970
        Supposed to be called by hostapd. Therefore first it checks for session, 
        if it is null creates it and then uses to query.
    '''       
    global session 
    if session is None:
        session = createDB_and_session()
    
    try:
        device = session.query(mac_sniffer.Device).filter_by(mac=mac_address).one()
        device.update_last_seen(wheninseconds)
    except sqlalchemy.orm.exc.NoResultFound:
        session.add(mac_sniffer.Device(MAC=mac_address,FIRST_SEEN=wheninseconds))
    finally:
        session.commit()