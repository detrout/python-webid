'''
Created on Jan 23, 2013

@author: ydurmus

'''

import sys
sys.path.append('../')

from webid.authorizer import DirectTrust,TransitiveTrust

TEST_SERVER =  "http://localhost:3000/" # you should also change from foaf profiles

class TestAuthorizer():
    def test_direct_authentication_success(self):
        """
        Tests for two devices have their owners' certificate
        """
        auth_uri = "%sfixtures/foaf/authenticator_direct.rdf"%TEST_SERVER
        supp_uri = "%sfixtures/foaf/supplicant_direct.rdf"%TEST_SERVER
        dt =  DirectTrust(supp_uri, auth_uri)
        assert dt.is_trusted
    
    def test_direct_authentication_same_owner(self):
        """
        Same person owns the two device and person's own certificate is in the devices
        """
        auth_uri = "%sfixtures/foaf/authenticator_direct.rdf"%TEST_SERVER
        dt =  DirectTrust(auth_uri, auth_uri)
        assert dt.is_trusted
    
    def test_direct_authentication_fail(self):
        """
        Users' certificates are in the machines however, guys don't know each other
        """
        auth_uri = "%sfixtures/foaf/authenticator_direct_fail.rdf"%TEST_SERVER
        supp_uri = "%sfixtures/foaf/supplicant_direct.rdf"%TEST_SERVER
        dt =  DirectTrust(supp_uri, auth_uri)
        assert not dt.is_trusted
    
    def test_transitive_authentication_success(self):
        """
        Both devices have 3 owners and their 2nd owners know each other
        """
        auth_uri = "%sfixtures/foaf/auth_trans.rdf"%TEST_SERVER
        supp_uri = "%sfixtures/foaf/supp_trans.rdf"%TEST_SERVER
        tt = TransitiveTrust(supp_uri, auth_uri)
        assert tt.is_trusted
        
    def test_transitive_authentication_no_common(self):
        """
        There is no common auth_trans_no_common is modified from auth_trans 
        without auth_trans_owner2
        """
        auth_uri = "%sfixtures/foaf/auth_trans_no_common.rdf"%TEST_SERVER
        supp_uri = "%sfixtures/foaf/supp_trans.rdf"%TEST_SERVER
        tt = TransitiveTrust(supp_uri, auth_uri)
        assert not tt.is_trusted
        
    def test_transitive_authentication_same_owner(self):
        """
        Owner is the same for both devices
        """
        auth_uri = "%sfixtures/foaf/auth_trans_same_owner.rdf"%TEST_SERVER
        supp_uri = "%sfixtures/foaf/supp_trans_same_owner.rdf"%TEST_SERVER
        tt = TransitiveTrust(supp_uri, auth_uri)
        assert tt.is_trusted
        