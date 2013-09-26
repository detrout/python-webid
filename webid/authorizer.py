'''
Created on Jan 22, 2013

@author: ydurmus
'''

import logging

from sqlalchemy.orm import subqueryload

import constants
from fetcher import WebIDLoader
from sniffer import mac_sniffer
import sniffer


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
        Loads the profile
        """
        print "profile:", profile.uri
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
            logger.debug("ASK_QUERY to %s = \n%s"%(profile.uri,ask_query))
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
            
            if not isinstance(profile,WebIDLoader): profile = WebIDLoader(profile) 
            self.load_the_graph(profile)
            res = profile.graph.query(constants.FIND_FRIENDS)
            friends = map(lambda x: x[0].__str__(),res)
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
    

class Trust(TransitiveTrust):
    """
    In this class 3 different trust connections are done at once.
    First SameOwner is checked
    Second Direct Friends are checked. (It has a different notion than DirectTrust)
    Third InDirectFriends are checked. (Different than transitive trust)
    
    Forward-Backward hybrid algorithm is used to search for trust.
    
    
    
    Steps:
    Get AuthenticatorOwners
    Get SupplicantOwners
    If there exists a common owner than verify that owner knows the supplicant (SAME OWNER)
    
    If not SameOwner
    Fetch friend list of each authenticator owners.
    If supplicant owners are in the list of direct friends then verify friend. (Direct Friends)
    
    If not Direct Friends
    Fetch friend list of each supplicant owners.
    If there exists a common friend, then verify the friend that it knows the supplicant. (InDirect Friends)
    
    if not: Fail
    
    """
    def __init__(self,SUPP_URI,AUTH_URI, MAC_LIST):
        
        super(Trust,self).__init__(SUPP_URI,AUTH_URI)
        
        self.supp_uri = SUPP_URI
        self.auth_uri = AUTH_URI
        self.mac_list = filter(lambda x: x != "", MAC_LIST.split("|"))
        logger.debug("The existing mac list is %s",self.mac_list)
        if sniffer.session is None:
            sniffer.session = sniffer.createDB_and_session()
        
    
    @property
    def is_trusted(self):
        return self.same_owner() or self.direct_friends() or self.indirect_friends() 
    
    def same_owner(self):
        common_owners = filter(lambda x: x in self.supplicant_owners, self.authorizer_owners) 
        logger.debug("Common friends for auth:%s \nsupplicant owners %s \nare: %s "%
                         (self.authorizer_owners,self.supplicant_owners,common_owners ))
        
        for common in common_owners:
            # Now Let's verify the this common owner knows the supplicant device.             
            if self.check_for_link(WebIDLoader(common), self.supp_uri, True):
                logger.debug("SAME_OWNER: Auth:%s  and Supp:%s have same owner:%s",self.auth_uri,self.supp_uri, common)
                return True 
            else:
                self.supplicant_owners.remove(common)           
        return False
    
    
    def direct_friends(self):
        self.auth_owner_friend_map = {}
        logger.debug("Looking for Direct Friends")
        for auth_owner in self.authorizer_owners:
            friends_of_auth_owner =  self.fetch_friends(auth_owner)
            self.auth_owner_friend_map[auth_owner] = friends_of_auth_owner
            common_direct_friends =  filter(lambda x: x in friends_of_auth_owner, self.supplicant_owners)
            
            for common in common_direct_friends:
                #Consider sorted lists and binary search for performance improvement
                if self.check_for_link(WebIDLoader(common), self.supp_uri, False):
                    logger.debug("DIRECT_FRIEND: Auth:%s  and Supp:%s has direct_friend:%s",self.auth_uri,self.supp_uri, common)
                    return True
                else:
                    self.supplicant_owners.remove(common) 
        return False
    
    def indirect_friends(self):
        logger.debug("Looking for indirect friends")
        self.supp_owner_friend_map = {}
        for auth_owner in self.authorizer_owners:
            if not self.auth_owner_friend_map.has_key(auth_owner):  
                self.auth_owner_friend_map[auth_owner] = self.fetch_friends(auth_owner)
            
            
            for supp_owner in reversed(self.supplicant_owners):
                if not  self.supp_owner_friend_map.has_key(supp_owner):
                    self.supp_owner_friend_map[supp_owner] =  self.fetch_friends(supp_owner)
                if self.supp_uri not in self.supp_owner_friend_map[supp_owner]:  # it seems that supplicant device is making up new artificial owners.
                    self.supp_owner_friend_map.remove(supp_owner)
                    self.supplicant_owners.remove(supp_owner)
                    continue
                
                common_friends = filter(lambda x : x in self.auth_owner_friend_map[auth_owner], 
                                        self.supp_owner_friend_map[supp_owner])
                logger.debug("common indirect friends:  %s",common_friends)
                logger.debug("supp uri: %s \n supp_owner_friends:%s ",self.supp_uri,self.supp_owner_friend_map[supp_owner])
                for common in common_friends:
                    if self.check_for_link(WebIDLoader(common), supp_owner, False): 
                            logger.debug("InDIRECT_FRIEND: Auth:%s  and Supp:%s has indirect_friend:%s",self.auth_uri,self.supp_uri, common)
                            return True
                    else:    # supplicant owner to common friend there is one directional relation. common person does not know supp owner.
                        self.supp_owner_friend_map[supp_owner].remove(common)
        return False

# The below methods are supposed to be called by C 

def __direct_trust(auth_uri,supp_uri):
    """
    This method is used to call the direct_trust class from C
    """  
    dt =  DirectTrust(supp_uri, auth_uri)
    #print "In python code is the connection trusted: ",dt.is_trusted
    return dt.is_trusted

def __transitive_trust(auth_uri,supp_uri):
    """
    This method is used to call the transitive_trust class from C
    """    
    tt =  TransitiveTrust(supp_uri, auth_uri)
    #print "In python code is the connection trusted: ",tt.is_trusted
    return tt.is_trusted

def __trust(auth_uri,supp_uri,maclist,wheninseconds):
    """
    This method is used to call the trust class from C
    """    
    
    t = Trust(supp_uri,auth_uri,maclist)
    if t.is_trusted:
        
        logger.debug("Mac list is %s",t.mac_list)
        if len(t.mac_list) == 1:
            try:
                d = sniffer.session.query(mac_sniffer.Device).options(subqueryload('owners')).filter_by(mac=t.mac_list[0]).first()
                logger.debug("Device is %s",d)
                d.uri = supp_uri

                for owner in d.owners:
                    t.supplicant_owners.remove(owner.uri)
                for missing_owner_uri in t.supplicant_owners:
                    p = mac_sniffer.Person(URI=missing_owner_uri)
                    d.owners.append(p)
                logger.debug("Owners are: %s", d.owners)
                sniffer.session.commit()
            except Exception as e:
                logger.error("Database exception: %s", e)
        
        
        return True
    return False
