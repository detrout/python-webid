'''
Created on Jan 22, 2013

@author: ydurmus
'''

from fetcher import WebIDLoader
from rdflib import URIRef
import constants
import logging
logger = logging.getLogger(name=__name__)


class URIisNotReachable(Exception):
    """
    stub.
    The links may be broken, or any other problem that leads to an invalid response
    """
    pass


def is_profile_reachable(profile):
    return (hasattr(profile,'ok') and profile.ok)

class DirectTrust(object):
    """
    Checks whether there is a direct connection between the peers.
    In Social Machines: the device owners' own certificate is used. 
    Therefore, there has to be a direct foaf:knows link in the personal
    profile document. 
    """
    
    def __init__(self, SAN_URI, OWN_URI):
        """
        Since the certificate has already been authenticated, we just need the URI value under
        Subject Alternative Name (SAN).
        OWN_URI is the public profile URI of the owner of the authorizer device.
        """
        self.san_uri = SAN_URI
        self.own_uri = OWN_URI
        self.own_profile = WebIDLoader(OWN_URI)
        
    
    def load_the_graph(self,profile):
        """
        Loads the own profile
        """
        if not is_profile_reachable(profile):
            profile.get()
            if is_profile_reachable(profile): # GET might not be able to fetch any data
                profile.parse(None) #We are not sure about the format
            else:
                raise URIisNotReachable("URI:%s is not reachable."%profile.uri) 
            
        
    def check_for_link(self,profile, friend_uri, self_link=True):
        """
        Checks for a foaf:knows link in OWN_URI for SAN_URI. IF a link exists this is interpreted 
        as OWN_URI holder trusts SAN_URI. 
        If self_link is true then people can be friends with themselves.
        """
        # we assume that people are friends of each other
        if(self_link & (profile.uri == friend_uri)):
            logger.debug("The person itself is being check for friendship")
            return True   
        try:      
            self.load_the_graph(profile)   
            ask_query = constants.KNOWS_CHECK.format(target_uri=friend_uri)    
            #logger.debug("ASK_QUERY = \n%s"%ask_query)
            result = profile.graph.query(ask_query)
            return result.__iter__().next()
        except URIisNotReachable as ex:
            logger.warning(ex)
            return False
    
    @property 
    def is_trusted(self):
        """
        Main method to check for a direct trust link.
        """
        return self.check_for_link(self.own_profile,self.san_uri)
    

        
    

class TransitiveTrust(DirectTrust):
    """
    Checks whether there is a transitive connection between the peers.
    In Social Machines: Devices have their own certificates and profiles on the web.
    First, we should find their owners' profiles and then look for links between them.
    """
    
    def __init__(self,SAN_URI,OWN_URI):
        super(TransitiveTrust,self).__init__(SAN_URI,OWN_URI)
        # Supplicant is the requester device
        self.supplicant_profile =  WebIDLoader(SAN_URI)
        self.supplicant_owners = self.fetch_friends(self.supplicant_profile) 
        
        # Authorizer is the device that runs this code
        self.authorizer_profile = WebIDLoader(OWN_URI)
        self.authorizer_owners = self.fetch_friends(self.authorizer_profile)
    
    def fetch_friends(self,profile):
        """ 
        Returns a LIST of friends, Friends are defined with foaf:knows relations
        Gets a WebIDLoader as profile
        """
        try:
            self.load_the_graph(profile)
            res = profile.graph.query(constants.FIND_FRIENDS)
            friends = map(lambda x: x[0],res)
            logger.debug("Friends of %s are %s"%(profile.uri,friends))
            return friends
        except URIisNotReachable as ex:
            logger.warning(ex)
            return []
        
    @property
    def is_trusted(self):
        
        for auth_owner in self.authorizer_owners:
            auth_profile = WebIDLoader(auth_owner)
            if not self.check_for_link(auth_profile, self.own_uri):
                logger.debug("Authorizer claims that %s is its owner but is NOT, skipping..."%auth_owner)
                continue
            auth_friends = self.fetch_friends(auth_profile)
            # find intersection 
            #  we are adding auth owner to the list since there may be a common owner. Auth owner can be the
            # owner of both devices.
            common_friends = filter(lambda x: x in self.supplicant_owners, auth_friends+[auth_owner]) 
            logger.debug("Common friends for auth:%s \nsupplicant owners %s \nare: %s "%
                         (auth_owner,self.supplicant_owners,common_friends ))
            for common in common_friends:
                common_profile = WebIDLoader(common)
                # Also check whether 
                if self.check_for_link(common_profile, self.san_uri):
                    logger.info("SUCCESS!: supp owner: %s <-> auth owner: %s"%
                                 (common,auth_owner))
                    return True
                else:
                    # the supplicant claims that common is one of its owners. However, it turns out that
                    # common does not have a link to the supplicant. Therefore, we remove common from
                    #owner list.
                    self.supplicant_owners.remove(common)
                    logger.info("Supplicant claims that %s is its owner but it turned out NOT "%common)
                    
        return False
