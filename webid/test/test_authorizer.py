'''
Created on Jan 23, 2013

@author: ydurmus

'''
import os
import six

import requests_mock

from webid.authorizer import DirectTrust, TransitiveTrust
from webid.constants import FORMATS
from pkg_resources import resource_string


class TestAuthorizer():
    HOST = 'http://localhost:3000/'

    def add_fixture(self, m, pathname):
        _, ext = os.path.splitext(pathname)
        uri = TestAuthorizer.HOST + pathname
        text = resource_string(__name__, pathname)
        if six.PY3:
            text = text.decode()
        headers = {
            'content-type': FORMATS[ext[1:]],
        }

        m.register_uri('GET', uri, headers=headers, text=text)
        return uri

    def add_404(self, m, pathname):
        uri = TestAuthorizer.HOST + pathname
        m.register_uri('GET', uri, status_code=404)
        return uri

    def add_common(self, m):
        self.add_fixture(m, 'fixtures/foaf/auth_trans_both_owner.rdf')
        self.add_fixture(m, 'fixtures/foaf/auth_trans_owner1.rdf')
        self.add_fixture(m, 'fixtures/foaf/auth_trans_owner2.rdf')
        self.add_fixture(m, 'fixtures/foaf/auth_trans_owner3.rdf')
        self.add_fixture(m, 'fixtures/foaf/supp_trans_owner1.rdf')
        self.add_fixture(m, 'fixtures/foaf/supp_trans_owner2.rdf')
        self.add_fixture(m, 'fixtures/foaf/supp_trans_owner3.rdf')
        self.add_404(m, 'fixtures/foaf/dummy.rdf')

    def test_direct_authentication_success(self):
        """
        Tests for two devices have their owners' certificate
        """
        with requests_mock.Mocker() as m:
            auth_uri = self.add_fixture(m, 'fixtures/foaf/authenticator_direct.rdf')
            supp_uri = self.add_fixture(m, 'fixtures/foaf/supplicant_direct.rdf')
            dt = DirectTrust(supp_uri, auth_uri)
            dt.check_for_link(dt.own_profile, dt.san_uri)
            assert dt.is_trusted

    def test_direct_authentication_same_owner(self):
        """
        Same person owns the two device and person's own certificate is in the devices
        """
        with requests_mock.Mocker() as m:
            auth_uri = self.add_fixture(m, 'fixtures/foaf/authenticator_direct.rdf')
            dt = DirectTrust(auth_uri, auth_uri)
            assert dt.is_trusted

    def test_direct_authentication_fail(self):
        """
        Users' certificates are in the machines however, guys don't know each other
        """
        with requests_mock.Mocker() as m:
            auth_uri = self.add_fixture(m, 'fixtures/foaf/authenticator_direct_fail.rdf')
            supp_uri = self.add_fixture(m, 'fixtures/foaf/supplicant_direct.rdf')
            dt = DirectTrust(supp_uri, auth_uri)
            assert not dt.is_trusted

    def test_transitive_authentication_success(self):
        """
        Both devices have 3 owners and their 2nd owners know each other
        """
        with requests_mock.Mocker() as m:
            self.add_common(m)
            auth_uri = self.add_fixture(m, 'fixtures/foaf/auth_trans.rdf')
            supp_uri = self.add_fixture(m, 'fixtures/foaf/supp_trans.rdf')
            # the graph loader finds these urls from the above documents
            tt = TransitiveTrust(supp_uri, auth_uri)
            assert tt.is_trusted

    def test_transitive_authentication_no_common(self):
        """
        There is no common auth_trans_no_common is modified from auth_trans
        without auth_trans_owner2
        """
        with requests_mock.Mocker() as m:
            self.add_common(m)
            auth_uri = self.add_fixture(m, 'fixtures/foaf/auth_trans_no_common.rdf')
            supp_uri = self.add_fixture(m, 'fixtures/foaf/supp_trans.rdf')
            tt = TransitiveTrust(supp_uri, auth_uri)
            assert not tt.is_trusted

    def test_transitive_authentication_same_owner(self):
        """
        Owner is the same for both devices
        """
        with requests_mock.Mocker() as m:
            self.add_common(m)
            auth_uri = self.add_fixture(m, 'fixtures/foaf/auth_trans_same_owner.rdf')
            supp_uri = self.add_fixture(m, 'fixtures/foaf/supp_trans_same_owner.rdf')
            tt = TransitiveTrust(supp_uri, auth_uri)
            assert tt.is_trusted
