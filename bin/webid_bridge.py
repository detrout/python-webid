

from webid.authorizer import DirectTrust,TransitiveTrust

TEST_SERVER = "http://localhost:3000/"

def direct_trust(auth_uri,san_uri):
    print "Will try to find a link from SAN:",san_uri," to auth: ", auth_uri
    
    auth_uri = "%sfixtures/foaf/%s"%(TEST_SERVER, auth_uri)
    supp_uri = "%sfixtures/foaf/%s"%(TEST_SERVER, san_uri)
    dt =  DirectTrust(supp_uri, auth_uri)
    #print "In python code is the connection trusted: ",dt.is_trusted
    return dt.is_trusted

def transitive_trust(auth_uri,san_uri):
    print "Will try to find a link from SAN:",san_uri," to auth: ", auth_uri
    
    auth_uri = "%sfixtures/foaf/%s"%(TEST_SERVER, auth_uri)
    supp_uri = "%sfixtures/foaf/%s"%(TEST_SERVER, san_uri)
    tt =  TransitiveTrust(supp_uri, auth_uri)
    #print "In python code is the connection trusted: ",tt.is_trusted
    return tt.is_trusted
    


