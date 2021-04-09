import base64
import json
import os

from contextlib import closing
from urllib.parse import urlparse, parse_qs

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.timezone import datetime
from django.shortcuts import reverse
from django.test import override_settings
from django.test.client import RequestFactory

from badgrsocialauth.models import Saml2Configuration, Saml2Account
from badgrsocialauth.views import auto_provision, saml2_client_for, create_saml_config_for
from badgrsocialauth.utils import set_session_authcode, set_session_badgr_app, userdata_from_saml_assertion

from badgeuser.models import CachedEmailAddress, BadgeUser

from mainsite.models import BadgrApp
from mainsite.tests import BadgrTestCase
from mainsite import TOP_DIR
from mainsite.utils import set_url_query_params

from saml2 import config, saml, BINDING_SOAP, BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import authn_context_class_ref

# TODO: Revert to library code once library is fixed for python3
# from saml2.metadata import create_metadata_string
from badgrsocialauth.saml2_utils import create_metadata_string

from saml2.saml import AuthnContext, AuthnStatement, NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, \
    NAME_FORMAT_BASIC, AUTHN_PASSWORD_PROTECTED
from saml2.server import Server
from saml2.s_utils import MissingValue


class SAML2Tests(BadgrTestCase):
    def setUp(self):
        super(SAML2Tests, self).setUp()
        self.test_files_path = os.path.join(TOP_DIR, 'apps', 'badgrsocialauth', 'testfiles')
        self.idp_metadata_for_sp_config_path = os.path.join(self.test_files_path, 'idp-metadata-for-saml2configuration.xml')

        with open(self.idp_metadata_for_sp_config_path, 'r') as f:
            metadata_xml = f.read()
        self.config = Saml2Configuration.objects.create(
            metadata_conf_url="http://example.com",
            slug="saml2.test",
            cached_metadata=metadata_xml
        )
        self.badgr_app = BadgrApp.objects.create(
            ui_login_redirect="https://example.com",
            ui_signup_failure_redirect='https://example.com/fail'
        )
        self.badgr_app.is_default = True
        self.badgr_app.save()
        self.ipd_cert_path = os.path.join(self.test_files_path, 'idp-test-cert.pem')
        self.ipd_key_path = os.path.join(self.test_files_path, 'idp-test-key.pem')
        self.sp_acs_location = 'http://localhost:8000/account/saml2/{}/acs/'.format(self.config.slug)

    def _skip_if_xmlsec_binary_missing(self):
        xmlsec_binary_path = getattr(settings, 'XMLSEC_BINARY_PATH', None)
        if xmlsec_binary_path is None:
            self.skipTest("SKIPPING: In order to test XML Signing, XMLSEC_BINARY_PATH to xmlsec1 must be configured.")

    def _initiate_login(self, idp_name, badgr_app, user=None):
        # Sets a BadgrApp in the session for later redirect, allows setting of a session authcode
        url = set_url_query_params(reverse('socialaccount_login'), provider=idp_name)

        if user is not None:
            self.client.force_authenticate(user=user)
            preflight_response = self.client.get(
                reverse('v2_api_user_socialaccount_connect') + '?provider={}'.format(idp_name)
            )
            location = urlparse(preflight_response.data['result']['url'])
            url = '?'.join([location.path, location.query])  # strip server info from location

        return self.client.get(url, HTTP_REFERER=badgr_app.ui_login_redirect)


    def test_signed_authn_request_option_creates_signed_metadata(self):
        self._skip_if_xmlsec_binary_missing()

        self.config.use_signed_authn_request = True
        self.config.save()
        with override_settings(
            SAML_KEY_FILE=self.ipd_key_path,
            SAML_CERT_FILE=self.ipd_cert_path):
            saml_client, config = saml2_client_for(self.config)
            self.assertTrue(saml_client.authn_requests_signed)
            self.assertNotEqual(saml_client.sec.sec_backend, None)

    def test_signed_authn_request_option_returns_self_posting_form_populated_with_signed_metadata(self):
        self._skip_if_xmlsec_binary_missing()
        self.config.use_signed_authn_request = True
        self.config.save()
        with override_settings(
            SAML_KEY_FILE=self.ipd_key_path,
            SAML_CERT_FILE=self.ipd_cert_path):
            authn_request = self.config
            url = '/account/sociallogin?provider=' + authn_request.slug
            redirect_url = '/account/saml2/' + authn_request.slug + '/'
            response = self.client.get(url, follow=True)
            intermediate_url, intermediate_url_status = response.redirect_chain[0]

            # login redirect to saml2 login
            self.assertEqual(intermediate_url, redirect_url)
            self.assertEqual(intermediate_url_status, 302)
            # self populated form generated with metadata file from self.ipd_metadata_path
            self.assertEqual(response.status_code, 200)
            # changing attribute location of element md:SingleSignOnService necessitates updating this value
            self.assertIsNot(
                response.content.find(b'<form action="https://example.com/saml2/idp/SSOService.php" method="post">'), -1)
            self.assertIsNot(
                response.content.find(b'<input type="hidden" name="SAMLRequest" value="'), -1)

    def test_egcc_response_500(self):
        from saml2 import entity

        idp_url = "https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/"
        idp_name = "saml2.egcc"
        metadata = '''<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="_f0dfbb62-6de1-48ea-b8ce-fb95e7383560" entityID="https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/">
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#_f0dfbb62-6de1-48ea-b8ce-fb95e7383560">
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<DigestValue>x7a34VS3i8BhaYrlEUMaq4Mt//Q04rbDd/ENT07p9YM=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>UEGV84D+KFqv5L8e69hU7KW0mkesrcYbe1Ql4asa9N+1a3hM3BRnP3NWVe03TKblQMD9ENlcdEBreB7gqYrq3XWeaBlzWRUUX9Wanw8LItoT7bgC4zX50m+wZ844oFYBTs7bxtfS4yecThsiPMS1Fy8CtnT6MFjm5jA+WiyPGYUjf+fGfLyCuYfgl5rOvjZbzbaePvtDvKVSjc97HcUidAOyEzdnC0O2w3/kjLF8bL+wBLhSsvoRozxw1TfF/aCg+k0U3c6HkaPAOHFjXjwR8fFRA5B+kKLiZmVzH07Gu9ScE/NWLKL1z3VKbctxZb9WK4BnV6kz7yvMIuFN5K5qbQ==</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQO06HXURtw6dDNl8QBHJMGjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMTIyMDAxNDNaFw0yNDAzMTIxOTAxNDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAquKiGHHJ428Y1iqQxRi2YHBfGhUhclQhJRn3phS4Z4+3Y2UIv8h2LSDu3QVL9k44EBfGMIWp6HkgHeLya62OVmDhqH2/9udUKfhVxaYKu7Ak1/WzMr8TgUEm98RAL7ZFSM9xZ2p6fT2hD4gHLdCAkBBy6dnzIjM9vLYP82PiHsAGqkeTTHDZhGDWLvWdoMrrMkNkzDObwJzw2IlfkrHvZuimHyJbLhuAlIORa9dvQj8DM9hWLxP6HyJxtJ0mZYFLsLEfqiOMZN5/aUdFuQUIJQwMwqlvACkBLf/2GflEvSWj6gc1wlXhZdZqvshHrZl1qIDkLmsgr9gimUuP9XpJwQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBZ8YeaYeV7WHrPf+1Mcl3Rmt0n4x0+xiA+vdjB5q3gCXDhQgNl8CabwATpY/5ze6cwKeM4MIlgOwZTu86JKKc2nqDAiyF/gtbETGiTE2ucfQjyZyoCr6WSRj1vquoNSockzimEfiwMtnYvUAic/aEklljHz2m7TR6s938E1neE7lVU5Ig5IIvvE/3JbLgIM+CbgTHvZF7SfLAgdpMBPp9+nE6crsbQTYqi5exYeevZ5cwn5v6j1QIJh+s6f5+8IKuPfIxmJj2VDtm5TAo8JZSSr12hGK4VOaw3M/gbnJtxQQFvJfEtLwpgjo1fVqLK1wxchFHEE5HyYQUGogpPOV02</X509Certificate>
</X509Data>
</KeyInfo>
</Signature>
<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQO06HXURtw6dDNl8QBHJMGjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMTIyMDAxNDNaFw0yNDAzMTIxOTAxNDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAquKiGHHJ428Y1iqQxRi2YHBfGhUhclQhJRn3phS4Z4+3Y2UIv8h2LSDu3QVL9k44EBfGMIWp6HkgHeLya62OVmDhqH2/9udUKfhVxaYKu7Ak1/WzMr8TgUEm98RAL7ZFSM9xZ2p6fT2hD4gHLdCAkBBy6dnzIjM9vLYP82PiHsAGqkeTTHDZhGDWLvWdoMrrMkNkzDObwJzw2IlfkrHvZuimHyJbLhuAlIORa9dvQj8DM9hWLxP6HyJxtJ0mZYFLsLEfqiOMZN5/aUdFuQUIJQwMwqlvACkBLf/2GflEvSWj6gc1wlXhZdZqvshHrZl1qIDkLmsgr9gimUuP9XpJwQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBZ8YeaYeV7WHrPf+1Mcl3Rmt0n4x0+xiA+vdjB5q3gCXDhQgNl8CabwATpY/5ze6cwKeM4MIlgOwZTu86JKKc2nqDAiyF/gtbETGiTE2ucfQjyZyoCr6WSRj1vquoNSockzimEfiwMtnYvUAic/aEklljHz2m7TR6s938E1neE7lVU5Ig5IIvvE/3JbLgIM+CbgTHvZF7SfLAgdpMBPp9+nE6crsbQTYqi5exYeevZ5cwn5v6j1QIJh+s6f5+8IKuPfIxmJj2VDtm5TAo8JZSSr12hGK4VOaw3M/gbnJtxQQFvJfEtLwpgjo1fVqLK1wxchFHEE5HyYQUGogpPOV02</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<fed:ClaimTypesOffered>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
<auth:DisplayName>Name</auth:DisplayName>
<auth:Description>The mutable display name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier">
<auth:DisplayName>Subject</auth:DisplayName>
<auth:Description>An immutable, globally unique, non-reusable identifier of the user that is unique to the application for which a token is issued.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
<auth:DisplayName>Given Name</auth:DisplayName>
<auth:Description>First name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
<auth:DisplayName>Surname</auth:DisplayName>
<auth:Description>Last name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/displayname">
<auth:DisplayName>Display Name</auth:DisplayName>
<auth:Description>Display name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/nickname">
<auth:DisplayName>Nick Name</auth:DisplayName>
<auth:Description>Nick name of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant">
<auth:DisplayName>Authentication Instant</auth:DisplayName>
<auth:Description>The time (UTC) when the user is authenticated to Windows Azure Active Directory.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod">
<auth:DisplayName>Authentication Method</auth:DisplayName>
<auth:Description>The method that Windows Azure Active Directory uses to authenticate users.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/objectidentifier">
<auth:DisplayName>ObjectIdentifier</auth:DisplayName>
<auth:Description>Primary identifier for the user in the directory. Immutable, globally unique, non-reusable.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/tenantid">
<auth:DisplayName>TenantId</auth:DisplayName>
<auth:Description>Identifier for the user's tenant.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/identityprovider">
<auth:DisplayName>IdentityProvider</auth:DisplayName>
<auth:Description>Identity provider for the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
<auth:DisplayName>Email</auth:DisplayName>
<auth:Description>Email address of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">
<auth:DisplayName>Groups</auth:DisplayName>
<auth:Description>Groups of the user.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/accesstoken">
<auth:DisplayName>External Access Token</auth:DisplayName>
<auth:Description>Access token issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration">
<auth:DisplayName>External Access Token Expiration</auth:DisplayName>
<auth:Description>UTC expiration time of access token issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/identity/claims/openid2_id">
<auth:DisplayName>External OpenID 2.0 Identifier</auth:DisplayName>
<auth:Description>OpenID 2.0 identifier issued by external identity provider.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/claims/groups.link">
<auth:DisplayName>GroupsOverageClaim</auth:DisplayName>
<auth:Description>Issued when number of user's group claims exceeds return limit.</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
<auth:DisplayName>Role Claim</auth:DisplayName>
<auth:Description>Roles that the user or Service Principal is attached to</auth:Description>
</auth:ClaimType>
<auth:ClaimType xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="http://schemas.microsoft.com/ws/2008/06/identity/claims/wids">
<auth:DisplayName>RoleTemplate Id Claim</auth:DisplayName>
<auth:Description>Role template id of the Built-in Directory Roles that the user is a member of</auth:Description>
</auth:ClaimType>
</fed:ClaimTypesOffered>
<fed:SecurityTokenServiceEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:SecurityTokenServiceEndpoint>
<fed:PassiveRequestorEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:PassiveRequestorEndpoint>
</RoleDescriptor>
<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQO06HXURtw6dDNl8QBHJMGjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMTIyMDAxNDNaFw0yNDAzMTIxOTAxNDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAquKiGHHJ428Y1iqQxRi2YHBfGhUhclQhJRn3phS4Z4+3Y2UIv8h2LSDu3QVL9k44EBfGMIWp6HkgHeLya62OVmDhqH2/9udUKfhVxaYKu7Ak1/WzMr8TgUEm98RAL7ZFSM9xZ2p6fT2hD4gHLdCAkBBy6dnzIjM9vLYP82PiHsAGqkeTTHDZhGDWLvWdoMrrMkNkzDObwJzw2IlfkrHvZuimHyJbLhuAlIORa9dvQj8DM9hWLxP6HyJxtJ0mZYFLsLEfqiOMZN5/aUdFuQUIJQwMwqlvACkBLf/2GflEvSWj6gc1wlXhZdZqvshHrZl1qIDkLmsgr9gimUuP9XpJwQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBZ8YeaYeV7WHrPf+1Mcl3Rmt0n4x0+xiA+vdjB5q3gCXDhQgNl8CabwATpY/5ze6cwKeM4MIlgOwZTu86JKKc2nqDAiyF/gtbETGiTE2ucfQjyZyoCr6WSRj1vquoNSockzimEfiwMtnYvUAic/aEklljHz2m7TR6s938E1neE7lVU5Ig5IIvvE/3JbLgIM+CbgTHvZF7SfLAgdpMBPp9+nE6crsbQTYqi5exYeevZ5cwn5v6j1QIJh+s6f5+8IKuPfIxmJj2VDtm5TAo8JZSSr12hGK4VOaw3M/gbnJtxQQFvJfEtLwpgjo1fVqLK1wxchFHEE5HyYQUGogpPOV02</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<fed:TargetScopes>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/</wsa:Address>
</wsa:EndpointReference>
</fed:TargetScopes>
<fed:ApplicationServiceEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:ApplicationServiceEndpoint>
<fed:PassiveRequestorEndpoint>
<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
<wsa:Address>https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/wsfed</wsa:Address>
</wsa:EndpointReference>
</fed:PassiveRequestorEndpoint>
</RoleDescriptor>
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data>
<X509Certificate>MIIC8DCCAdigAwIBAgIQO06HXURtw6dDNl8QBHJMGjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMTIyMDAxNDNaFw0yNDAzMTIxOTAxNDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAquKiGHHJ428Y1iqQxRi2YHBfGhUhclQhJRn3phS4Z4+3Y2UIv8h2LSDu3QVL9k44EBfGMIWp6HkgHeLya62OVmDhqH2/9udUKfhVxaYKu7Ak1/WzMr8TgUEm98RAL7ZFSM9xZ2p6fT2hD4gHLdCAkBBy6dnzIjM9vLYP82PiHsAGqkeTTHDZhGDWLvWdoMrrMkNkzDObwJzw2IlfkrHvZuimHyJbLhuAlIORa9dvQj8DM9hWLxP6HyJxtJ0mZYFLsLEfqiOMZN5/aUdFuQUIJQwMwqlvACkBLf/2GflEvSWj6gc1wlXhZdZqvshHrZl1qIDkLmsgr9gimUuP9XpJwQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBZ8YeaYeV7WHrPf+1Mcl3Rmt0n4x0+xiA+vdjB5q3gCXDhQgNl8CabwATpY/5ze6cwKeM4MIlgOwZTu86JKKc2nqDAiyF/gtbETGiTE2ucfQjyZyoCr6WSRj1vquoNSockzimEfiwMtnYvUAic/aEklljHz2m7TR6s938E1neE7lVU5Ig5IIvvE/3JbLgIM+CbgTHvZF7SfLAgdpMBPp9+nE6crsbQTYqi5exYeevZ5cwn5v6j1QIJh+s6f5+8IKuPfIxmJj2VDtm5TAo8JZSSr12hGK4VOaw3M/gbnJtxQQFvJfEtLwpgjo1fVqLK1wxchFHEE5HyYQUGogpPOV02</X509Certificate>
</X509Data>
</KeyInfo>
</KeyDescriptor>
<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/saml2"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/saml2"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/2f277f1e-e5f1-4f62-b595-79c2d13afda4/saml2"/>
</IDPSSODescriptor>
</EntityDescriptor>
'''

        Saml2Configuration.objects.create(
            metadata_conf_url=idp_url, cached_metadata=metadata, slug=idp_name)
        saml_client, config = saml2_client_for(idp_name)

        saml_xml_response = '<samlp:Response ID="_6bfff445-8077-42ac-ac02-fd68ee76e932" Version="2.0" IssueInstant="2021-04-09T12:53:30.562Z" Destination="https://api.test.badgr.com/account/saml2/saml2.egcc/acs/" InResponseTo="id-dxvhOj4HsG9rlVDVx" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion ID="_81f43d08-ad43-4d90-83f6-0ef40b4a1f00" IssueInstant="2021-04-09T12:53:30.552Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/</Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_81f43d08-ad43-4d90-83f6-0ef40b4a1f00"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>4Q0j6rn4Mxr2rrbfdqo6R9Bosg8slDbCemFDeLrbIbk=</DigestValue></Reference></SignedInfo><SignatureValue>nNJq4aEHemXDcqmLH/tZ/GyNaiebXsC6twu/cIW+WqcFQwG4zTSxP0DiGlwdkCfvP9j9nwiabGsGzGIsbD0ltO+Mrd8TC6xd6/ufwOpGjvtl9FIx00/9AiVDI9sWw4EHnrkkRwIF8dWRqovNoUnYg3GVDDWKTuCTFvqBM0w4uVnMXUw4vLEvuvWJ5il5O+x1u6Sc1Rg53sHDGRS1psRkN2/+FDMae2gTWRFWpQNMa25XEVXjbsQQk2QNe7rHWfn+nD/rPfFXedrr0ye74O1Joaiv/SUKGrH9p1WUhO3/e2IMAr8KMTRCPU2egrxIBio6mbvxZM6ZtagFFL/trTnwkQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQe1BF93yCAKJFf+x3pg6UaTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTA0MDUyMDAxMzlaFw0yNDA0MDUyMDAxMzlaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0WNU1RMo8Pft5Grnr9RHcip0WF4lGA5JkxYgmViVZsO0vihNpG3YYy7GKn+9yosp73sVZ8FBK1UQHScd5yZet8XxM0C8CoXox6t+hUpLzzDNe3dTiwBu3aNx+BUbhLOEWTwguTv8RRniNzk3ESEUwZRb05Cu9aDCz4asiVKI0z3ZcKodBDDInDsJlc91x67y2nhWSDarMwB8U/r+7gG5hiAWwoKONzcP7b/jEsaH9ueOXCEGPsaeIwHVzWfRUTu1RGeItzNZrMTiAcymFTkwj8l9/0jXZHFosO6HtiBGWJL55oyu81dYVYDIgAkBvvkmaofNayYDJMTAfIHiCT5IQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQC7wygtt7WnKLfHVwTEf/T4ZoYEcxLjWUnGqSa0x5aOZUA6k5c8VPZxqHnShADO/hjQw6DWHysdB8/FuB2jmijfRZ5MSnjosKRvpWLFmspwMpSewNKy+mBVJ0QnpEPXQKlTazBdmw7WGHEAXsG4iMWtkTLZhmKuFukOdCl27qlkBa8OTlBj7uaXRFGmmPgnVI+AjuPrkdMUVuNCCWCy7aNjNjNK5H02jnrwyV3o6ZM0iYdUnX0Urz737YP+gS75DGePAGMXEPQ8ryeriS/FQ9M6/2ptZHLBZ5uCQ4XOShjeDU/qbRW//PFdgKyEtVDhCLwcKfScW2JluwkZ7RHg+m8l</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">SDent1234@student.egcc.edu</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="id-dxvhOj4HsG9rlVDVx" NotOnOrAfter="2021-04-09T13:53:30.402Z" Recipient="https://api.test.badgr.com/account/saml2/saml2.egcc/acs/"/></SubjectConfirmation></Subject><Conditions NotBefore="2021-04-09T12:48:30.402Z" NotOnOrAfter="2021-04-09T13:53:30.402Z"><AudienceRestriction><Audience>https://api.test.badgr.com/account/saml2/saml2.egcc/acs/</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>2f277f1e-e5f1-4f62-b595-79c2d13afda4</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>709cd037-9bbb-4dd2-a6ce-a8838ddcb62a</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/displayname"><AttributeValue>Stu Dent</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/2f277f1e-e5f1-4f62-b595-79c2d13afda4/</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Stu</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Dent</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>SDent1234@student.egcc.edu</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>SDent1234@student.egcc.edu</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2021-04-09T12:53:00.335Z" SessionIndex="_81f43d08-ad43-4d90-83f6-0ef40b4a1f00"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>'
        saml_response = 'PHNhbWxwOlJlc3BvbnNlIElEPSJfZmNkMWI5NjktNmM2Zi00NDE4LWE0Y2YtYzBjNDQ5ZWU4YWZlIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMS0wNC0wOVQxMzowNjozOS4wODhaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9hcGkudGVzdC5iYWRnci5jb20vYWNjb3VudC9zYW1sMi9zYW1sMi5lZ2NjL2Fjcy8iIEluUmVzcG9uc2VUbz0iaWQtU2c5c1ZoNDVmRnRJRFpCUloiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJmMjc3ZjFlLWU1ZjEtNGY2Mi1iNTk1LTc5YzJkMTNhZmRhNC88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfMWYyYzQ3NGMtOThlYS00MjM4LTljYzUtMzQxMmIwYjYyMDAwIiBJc3N1ZUluc3RhbnQ9IjIwMjEtMDQtMDlUMTM6MDY6MzkuMDc4WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PElzc3Vlcj5odHRwczovL3N0cy53aW5kb3dzLm5ldC8yZjI3N2YxZS1lNWYxLTRmNjItYjU5NS03OWMyZDEzYWZkYTQvPC9Jc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjXzFmMmM0NzRjLTk4ZWEtNDIzOC05Y2M1LTM0MTJiMGI2MjAwMCI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PERpZ2VzdFZhbHVlPkNMZWY5cU5jdnZPY280K3FQWDRJMDVtNW5wS0I3WVJueE8weWNHL2ZXakE9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8+PFNpZ25hdHVyZVZhbHVlPmVJNzI4K2ZtV3FJbnk3MEVITzhtTkI1ZEhpdENwMk50MnpycjNwNSs1NzEvOVc3VThLRmhYcnNvZ1ArZjJwNldyT3ZDWXdGSDBPUTVPdSswYUdWUzgvb2NUOTlTYmhrMnVrdzQwS0JTSEllNGFkSkJ3N1A3VTUyd1IzR2paaXczdWJHWld0aG9rMForTFVVZmRlWHJKRndJVkdJSVp4ejcvMyt3TU5DU3hOS0xreDQzb3BFYnJJL1Fsc1d1MUZtd1BDd0o2QW5peXp0RTRFbWNoVVY0cFVDRjN3Z0d4Mnl4a082cEZiTkJ4V3RvNlIzeFNCbHBCZEl0TzFKVnhBb0U0MEgzTGx0ZGdHVTAybFBqdEtXTmQvWmtHaEg1OHkyZGRYZ1VzZXlaOENpZDNMY1FLaGJHRGtjV1hVN0pKeVB5RkI2Z2ZWWWlQZGc5UHBhcjZ6ZDExZz09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE+PFg1MDlDZXJ0aWZpY2F0ZT5NSUlDOERDQ0FkaWdBd0lCQWdJUWUxQkY5M3lDQUtKRmYreDNwZzZVYVRBTkJna3Foa2lHOXcwQkFRc0ZBREEwTVRJd01BWURWUVFERXlsTmFXTnliM052Wm5RZ1FYcDFjbVVnUm1Wa1pYSmhkR1ZrSUZOVFR5QkRaWEowYVdacFkyRjBaVEFlRncweU1UQTBNRFV5TURBeE16bGFGdzB5TkRBME1EVXlNREF4TXpsYU1EUXhNakF3QmdOVkJBTVRLVTFwWTNKdmMyOW1kQ0JCZW5WeVpTQkdaV1JsY21GMFpXUWdVMU5QSUVObGNuUnBabWxqWVhSbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeDBXTlUxUk1vOFBmdDVHcm5yOVJIY2lwMFdGNGxHQTVKa3hZZ21WaVZac08wdmloTnBHM1lZeTdHS24rOXlvc3A3M3NWWjhGQksxVVFIU2NkNXlaZXQ4WHhNMEM4Q29Yb3g2dCtoVXBMenpETmUzZFRpd0J1M2FOeCtCVWJoTE9FV1R3Z3VUdjhSUm5pTnprM0VTRVV3WlJiMDVDdTlhREN6NGFzaVZLSTB6M1pjS29kQkRESW5Ec0psYzkxeDY3eTJuaFdTRGFyTXdCOFUvcis3Z0c1aGlBV3dvS09OemNQN2IvakVzYUg5dWVPWENFR1BzYWVJd0hWeldmUlVUdTFSR2VJdHpOWnJNVGlBY3ltRlRrd2o4bDkvMGpYWkhGb3NPNkh0aUJHV0pMNTVveXU4MWRZVllESWdBa0J2dmttYW9mTmF5WURKTVRBZklIaUNUNUlRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFDN3d5Z3R0N1duS0xmSFZ3VEVmL1Q0Wm9ZRWN4TGpXVW5HcVNhMHg1YU9aVUE2azVjOFZQWnhxSG5TaEFETy9oalF3NkRXSHlzZEI4L0Z1QjJqbWlqZlJaNU1Tbmpvc0tSdnBXTEZtc3B3TXBTZXdOS3krbUJWSjBRbnBFUFhRS2xUYXpCZG13N1dHSEVBWHNHNGlNV3RrVExaaG1LdUZ1a09kQ2wyN3Fsa0JhOE9UbEJqN3VhWFJGR21tUGduVkkrQWp1UHJrZE1VVnVOQ0NXQ3k3YU5qTmpOSzVIMDJqbnJ3eVYzbzZaTTBpWWRVblgwVXJ6NzM3WVArZ1M3NURHZVBBR01YRVBROHJ5ZXJpUy9GUTlNNi8ycHRaSExCWjV1Q1E0WE9TaGplRFUvcWJSVy8vUEZkZ0t5RXRWRGhDTHdjS2ZTY1cySmx1d2taN1JIZyttOGw8L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48U3ViamVjdD48TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5TRGVudDEyMzRAc3R1ZGVudC5lZ2NjLmVkdTwvTmFtZUlEPjxTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iaWQtU2c5c1ZoNDVmRnRJRFpCUloiIE5vdE9uT3JBZnRlcj0iMjAyMS0wNC0wOVQxNDowNjozOC44NzhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vYXBpLnRlc3QuYmFkZ3IuY29tL2FjY291bnQvc2FtbDIvc2FtbDIuZWdjYy9hY3MvIi8+PC9TdWJqZWN0Q29uZmlybWF0aW9uPjwvU3ViamVjdD48Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjEtMDQtMDlUMTM6MDE6MzguODc4WiIgTm90T25PckFmdGVyPSIyMDIxLTA0LTA5VDE0OjA2OjM4Ljg3OFoiPjxBdWRpZW5jZVJlc3RyaWN0aW9uPjxBdWRpZW5jZT5odHRwczovL2FwaS50ZXN0LmJhZGdyLmNvbS9hY2NvdW50L3NhbWwyL3NhbWwyLmVnY2MvYWNzLzwvQXVkaWVuY2U+PC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvdGVuYW50aWQiPjxBdHRyaWJ1dGVWYWx1ZT4yZjI3N2YxZS1lNWYxLTRmNjItYjU5NS03OWMyZDEzYWZkYTQ8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvb2JqZWN0aWRlbnRpZmllciI+PEF0dHJpYnV0ZVZhbHVlPjcwOWNkMDM3LTliYmItNGRkMi1hNmNlLWE4ODM4ZGRjYjYyYTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9kaXNwbGF5bmFtZSI+PEF0dHJpYnV0ZVZhbHVlPlN0dSBEZW50PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL2lkZW50aXR5cHJvdmlkZXIiPjxBdHRyaWJ1dGVWYWx1ZT5odHRwczovL3N0cy53aW5kb3dzLm5ldC8yZjI3N2YxZS1lNWYxLTRmNjItYjU5NS03OWMyZDEzYWZkYTQvPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vY2xhaW1zL2F1dGhubWV0aG9kc3JlZmVyZW5jZXMiPjxBdHRyaWJ1dGVWYWx1ZT5odHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvYXV0aGVudGljYXRpb25tZXRob2QvcGFzc3dvcmQ8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIj48QXR0cmlidXRlVmFsdWU+U3R1PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3N1cm5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5EZW50PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI+PEF0dHJpYnV0ZVZhbHVlPlNEZW50MTIzNEBzdHVkZW50LmVnY2MuZWR1PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5TRGVudDEyMzRAc3R1ZGVudC5lZ2NjLmVkdTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyMS0wNC0wOVQxMzowNjozNi42OTNaIiBTZXNzaW9uSW5kZXg9Il8xZjJjNDc0Yy05OGVhLTQyMzgtOWNjNS0zNDEyYjBiNjIwMDAiPjxBdXRobkNvbnRleHQ+PEF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9BdXRobkNvbnRleHRDbGFzc1JlZj48L0F1dGhuQ29udGV4dD48L0F1dGhuU3RhdGVtZW50PjwvQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+'

        authn_response = saml_client.parse_authn_request_response(
            saml_response,
            entity.BINDING_HTTP_POST)
        self.assertTrue(True)

    def test_create_saml2_client(self):
        Saml2Configuration.objects.create(metadata_conf_url="http://example.com", cached_metadata="<xml></xml>",  slug="saml2.test2")
        client = saml2_client_for("saml2.test2")
        self.assertNotEqual(client, None)

    def test_oauth_to_saml2_redirection_flow(self):
        resp = self.client.get('/account/sociallogin?provider=' + self.config.slug)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/account/saml2/{}/'.format(self.config.slug))

    def test_login_with_registered_saml2_account(self):
        email = "test123@example.com"
        first_name = "firsty"
        last_name = "lastington"
        new_user = BadgeUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        # Auto verify emails
        cached_email = CachedEmailAddress.objects.get(email=email)
        cached_email.verified = True
        cached_email.save()
        Saml2Account.objects.create(config=self.config, user=new_user, uuid=email)
        badgr_app = BadgrApp.objects.create(ui_login_redirect="example.com", cors='example.com')
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_login_with_unregistered_saml2_account(self):
        email = "test456@example.com"
        first_name = "firsty"
        last_name = "lastington"
        badgr_app = self.badgr_app
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

    def test_login_with_email_variant(self):
        email = "testemail@example.com"
        first_name = "firsty"
        last_name = "lastington"
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

        email = "testEMAIL@example.com"
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertIn("authcode", resp.url)

    def test_saml2_login_with_conflicts(self):
        email = "test8679@example.com"
        email2 = "test234425@example.com"
        first_name = "firsty"
        last_name = "lastington"
        idp_name = self.config.slug
        badgr_app = self.badgr_app

        # email does not exist
        resp = auto_provision(
            None, ["different425@example.com"], first_name, last_name, self.config
        )
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        self.assertEqual(Saml2Account.objects.all().count(), 1)
        email_address = CachedEmailAddress.objects.get(email='different425@example.com')
        self.assertTrue(email_address.verified)
        self.assertTrue(email_address.primary)

        # email exists, but is unverified
        BadgeUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            send_confirmation=False
        )
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        email_address = CachedEmailAddress.objects.get(email=email)
        self.assertTrue(email_address.verified)
        self.assertTrue(email_address.primary)

        # Can auto provision again
        resp = auto_provision(None, [email], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)

        # email exists, but is verified
        BadgeUser.objects.create(
            email=email2,
            first_name=first_name,
            last_name=last_name,
            send_confirmation=False
        )
        cachedemail = CachedEmailAddress.objects.get(email=email2)
        cachedemail.verified = True
        cachedemail.save()
        saml_account_count = Saml2Account.objects.count()

        self._initiate_login(idp_name, badgr_app)
        resp = auto_provision(None, [email2], first_name, last_name, self.config)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authError=Could+not", resp.url)
        self.assertIn(self.config.slug, resp.url)
        self.assertEqual(saml_account_count, Saml2Account.objects.count(), "A Saml2Account must not have been created.")

        resp = self.client.get(resp.url)
        self.assertIn(self.config.slug, resp.url, "Query params are included in the response all the way back to the UI")

    def test_add_samlaccount_to_existing_user(self):
        # email exists, but is verified
        email = 'exampleuser@example.com'
        test_user = self.setup_user(
            email=email,
            token_scope='rw:profile rw:issuer rw:backpack'
        )

        preflight_response = self.client.get(
            reverse('v2_api_user_socialaccount_connect') + '?provider={}'.format(self.config.slug)
        )
        self.assertEqual(preflight_response.status_code, 200)
        location = urlparse(preflight_response.data['result']['url'])
        authcode = parse_qs(location.query)['authCode'][0]
        location = '?'.join([location.path, location.query])

        # the location now includes an auth code
        self.client.logout()
        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)
        location = response._headers['location'][1]

        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)

        # Can auto provision again
        rf = RequestFactory()
        fake_request = rf.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'saml_assertion': 'very fake'}
        )
        fake_request.session = dict()
        set_session_authcode(fake_request, authcode)

        resp = auto_provision(
            fake_request, [email], test_user.first_name, test_user.last_name, self.config
        )
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        account = Saml2Account.objects.get(user=test_user)

    def get_idp_config(self, meta=None):
        metadata_sp_1 = os.path.join(self.test_files_path, 'metadata_sp_1.xml')
        metadata_sp_2 = os.path.join(self.test_files_path, 'metadata_sp_2.xml')
        vo_metadata = os.path.join(self.test_files_path, 'vo_metadata.xml')
        attribute_map_dir = os.path.join(self.test_files_path, 'attributemaps')

        BASE = "http://localhost:8088"

        local_metadata = {"local": [metadata_sp_1, metadata_sp_2, vo_metadata]}
        metadata_source = local_metadata if meta is None else {'inline': [meta]}

        return {
            "entityid": "urn:mace:example.com:saml:roland:idp",
            "name": "Rolands IdP",
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [
                            ("%s/sso" % BASE, BINDING_HTTP_REDIRECT)],
                        "single_logout_service": [
                            ("%s/slo" % BASE, BINDING_SOAP),
                            ("%s/slop" % BASE, BINDING_HTTP_POST)]
                    },
                    "policy": {
                        "default": {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,  # means all I have
                            "name_form": NAME_FORMAT_URI,
                        },
                        self.sp_acs_location: {
                            "lifetime": {"minutes": 5},
                            "nameid_format": NAMEID_FORMAT_PERSISTENT,
                        },
                        "https://example.com/sp": {
                            "lifetime": {"minutes": 5},
                            "nameid_format": NAMEID_FORMAT_PERSISTENT,
                            "name_form": NAME_FORMAT_BASIC
                        }
                    },
                },
            },
            "debug": 1,
            "key_file": self.ipd_key_path,
            "cert_file": self.ipd_cert_path,
            "xmlsec_binary": getattr(settings, 'XMLSEC_BINARY_PATH', None),
            "metadata": metadata_source,
            "attribute_map_dir": attribute_map_dir,
            "organization": {
                "name": "Exempel AB",
                "display_name": [("Exempel AB", "se"), ("Example Co.", "en")],
                "url": "http://www.example.com/roland",
            },
            "contact_person": [
                {
                    "given_name": "John",
                    "sur_name": "Smith",
                    "email_address": ["john.smith@example.com"],
                    "contact_type": "technical",
                },
            ],
        }

    def get_authn_response(self, idp_config, identity):
        with closing(SamlServer(idp_config)) as server:
            name_id = server.ident.transient_nameid(
                "urn:mace:example.com:saml:roland:idp", "id12")

            authn_context_ref = authn_context_class_ref(AUTHN_PASSWORD_PROTECTED)
            authn_context = AuthnContext(authn_context_class_ref=authn_context_ref)

            locality = saml.SubjectLocality()
            locality.address = "172.31.25.30"

            authn_statement = AuthnStatement(
                subject_locality=locality,
                authn_instant=datetime.now().isoformat(),
                authn_context=authn_context,
                session_index="id12"
            )

            return server.create_authn_response(
                identity,
                "id12",  # in_response_to
                self.sp_acs_location,  # consumer_url. config.sp.endpoints.assertion_consumer_service:["acs_endpoint"]
                self.sp_acs_location,  # sp_entity_id
                name_id=name_id,
                sign_assertion=True,
                sign_response=True,
                authn_statement=authn_statement
            )

    def test_saml2_create_account(self):
        self._skip_if_xmlsec_binary_missing()
        self.config.use_signed_authn_request = True
        self.config.save()

        with override_settings(SAML_KEY_FILE=self.ipd_key_path, SAML_CERT_FILE=self.ipd_cert_path):
            saml2config = self.config
            sp_config = config.SPConfig()
            sp_config.load(create_saml_config_for(saml2config))
            sp_metadata = create_metadata_string('', config=sp_config, sign=True)

        idp_config = self.get_idp_config(sp_metadata)

        identity = {"eduPersonAffiliation": ["staff", "member"],
                    "surName": ["Jeter"], "givenName": ["Derek"],
                    "mail": ["foo@gmail.com"],
                    "title": ["shortstop"]}

        authn_response = self.get_authn_response(idp_config, identity)

        base64_encoded_response_metadata = base64.b64encode(authn_response.encode('utf-8'))
        base_64_utf8_response_metadata = base64_encoded_response_metadata.decode('utf-8')

        response = self.client.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'SAMLResponse': base_64_utf8_response_metadata}
        )

        self.assertEqual(response.status_code, 302)

        location = response._headers['location'][1]
        response = self.client.get(location)

        self.assertEqual(Saml2Account.objects.count(), 1)
        self.assertEqual(CachedEmailAddress.objects.count(), 1)
        self.assertEqual(BadgeUser.objects.count(), 1)

    def test_saml2_create_account_multiple_emails(self):
        self._skip_if_xmlsec_binary_missing()
        self.config.use_signed_authn_request = True
        self.config.save()

        with override_settings(SAML_KEY_FILE=self.ipd_key_path, SAML_CERT_FILE=self.ipd_cert_path):
            saml2config = self.config
            sp_config = config.SPConfig()
            sp_config.load(create_saml_config_for(saml2config))
            sp_metadata = create_metadata_string('', config=sp_config, sign=True)

        idp_config = self.get_idp_config(sp_metadata)

        identity = {"eduPersonAffiliation": ["staff", "member"],
                    "surName": ["Jeter"], "givenName": ["Derek"],
                    "mail": ["foo@gmail.com", "foo2@gmail.com"],
                    "title": ["shortstop"]}

        authn_response = self.get_authn_response(idp_config, identity)

        base64_encoded_response_metadata = base64.b64encode(authn_response.encode('utf-8'))
        base_64_utf8_response_metadata = base64_encoded_response_metadata.decode('utf-8')

        response = self.client.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'SAMLResponse': base_64_utf8_response_metadata}
        )

        self.assertEqual(response.status_code, 302)

        location = response._headers['location'][1]
        response = self.client.get(location)

        self.assertEqual(Saml2Account.objects.count(), 1)
        self.assertEqual(CachedEmailAddress.objects.count(), 2)
        self.assertEqual(BadgeUser.objects.count(), 1)

    def test_saml2_create_account_multiple_email_assertions(self):
        self._skip_if_xmlsec_binary_missing()
        self.config.use_signed_authn_request = True
        self.config.save()

        with override_settings(SAML_KEY_FILE=self.ipd_key_path, SAML_CERT_FILE=self.ipd_cert_path):
            saml2config = self.config
            sp_config = config.SPConfig()
            sp_config.load(create_saml_config_for(saml2config))
            sp_metadata = create_metadata_string('', config=sp_config, sign=True)

        idp_config = self.get_idp_config(sp_metadata)

        identity = {"eduPersonAffiliation": ["staff", "member"],
                    "surName": ["Jeter"], "givenName": ["Derek"],
                    "mail": ["foo@gmail.com", "foo2@gmail.com"],
                    "email": ["foo3@gmail.com"],
                    "title": ["shortstop"]}

        authn_response = self.get_authn_response(idp_config, identity)

        base64_encoded_response_metadata = base64.b64encode(authn_response.encode('utf-8'))
        base_64_utf8_response_metadata = base64_encoded_response_metadata.decode('utf-8')

        response = self.client.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'SAMLResponse': base_64_utf8_response_metadata}
        )

        self.assertEqual(response.status_code, 302)

        location = response._headers['location'][1]
        response = self.client.get(location)

        self.assertEqual(Saml2Account.objects.count(), 1)
        self.assertEqual(CachedEmailAddress.objects.count(), 3)
        self.assertEqual(BadgeUser.objects.count(), 1)

    def test_saml2_create_account_multiple_email_already_taken(self):
        self._skip_if_xmlsec_binary_missing()
        self.config.use_signed_authn_request = True
        self.config.save()

        email = 'exampleuser@example.com'
        t_user = self.setup_user(
            email=email,
            token_scope='rw:profile rw:issuer rw:backpack'
        )

        with override_settings(SAML_KEY_FILE=self.ipd_key_path, SAML_CERT_FILE=self.ipd_cert_path):
            saml2config = self.config
            sp_config = config.SPConfig()
            sp_config.load(create_saml_config_for(saml2config))
            sp_metadata = create_metadata_string('', config=sp_config, sign=True)

        idp_config = self.get_idp_config(sp_metadata)

        identity = {"eduPersonAffiliation": ["staff", "member"],
                    "surName": ["Jeter"], "givenName": ["Derek"],
                    "mail": ["foo@gmail.com", "foo2@gmail.com"],
                    "email": ["exampleuser@example.com"],
                    "title": ["shortstop"]}

        authn_response = self.get_authn_response(idp_config, identity)

        base64_encoded_response_metadata = base64.b64encode(authn_response.encode('utf-8'))
        base_64_utf8_response_metadata = base64_encoded_response_metadata.decode('utf-8')

        response = self.client.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'SAMLResponse': base_64_utf8_response_metadata}
        )

        self.assertEqual(response.status_code, 302)

        location = response._headers['location'][1]
        response = self.client.get(location)

        self.assertEqual(Saml2Account.objects.count(), 0)
        self.assertEqual(CachedEmailAddress.objects.count(), 1)
        self.assertEqual(BadgeUser.objects.count(), 1)

    def test_add_samlaccount_to_existing_user_with_varying_email(self):
        email = 'exampleuser@example.com'
        t_user = self.setup_user(
            email=email,
            token_scope='rw:profile rw:issuer rw:backpack'
        )

        preflight_response = self.client.get(
            reverse('v2_api_user_socialaccount_connect') + '?provider={}'.format(self.config.slug)
        )
        self.assertEqual(preflight_response.status_code, 200)
        location = urlparse(preflight_response.data['result']['url'])
        authcode = parse_qs(location.query)['authCode'][0]
        location = '?'.join([location.path, location.query])

        # the location now includes an auth code
        self.client.logout()
        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)
        location = response._headers['location'][1]
        response = self.client.get(location)
        self.assertEqual(response.status_code, 302)

        # Can auto provision again
        rf = RequestFactory()
        fake_request = rf.post(
            reverse('assertion_consumer_service', kwargs={'idp_name': self.config.slug}),
            {'saml_assertion': 'very fake'}
        )

        email2 = 'exampleuser_alt@example.com'
        resp = auto_provision(fake_request, [email2], t_user.first_name, t_user.last_name, self.config)
        self.assertEqual(resp.status_code, 302)

        fake_request.session = dict()
        set_session_authcode(fake_request, authcode)
        set_session_badgr_app(fake_request, self.badgr_app)
        fake_request.session['idp_name'] = self.config.slug

        resp = self.client.get(resp.url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("authToken", resp.url)
        self.assertIn(self.badgr_app.ui_login_redirect, resp.url)
        Saml2Account.objects.get(user=t_user)  # There is a Saml account associated with the user.
        CachedEmailAddress.objects.get(email=email2, user=t_user, verified=True, primary=False)  # User has the email.

        email3 = 'exampleuser_moredifferent@example.com'
        resp = auto_provision(fake_request, [email2, email3], t_user.first_name, t_user.last_name, self.config)

        CachedEmailAddress.objects.get(email=email3, user=t_user, verified=True, primary=False)  # User has new email.

    def test_can_extract_custom_userdata(self):
        self.config.custom_settings = json.dumps({
            'first_name': ['customMyClientFirstName']
        })
        self.config.save()
        reloaded_config = Saml2Configuration.objects.get(pk=self.config.pk)
        self.assertEqual(reloaded_config.custom_settings_data['email'], [], "default is set to an empty list")
        self.assertEqual(reloaded_config.custom_settings_data['first_name'], ['customMyClientFirstName'])

        fake_saml_assertion = {
            'emailaddress': ['moe@example.com'],
            'LastName': 'McMoe',
            'customMyClientFirstName': ['Moe']
        }

        self.assertEqual(
            userdata_from_saml_assertion(fake_saml_assertion, 'email', config=reloaded_config),
            fake_saml_assertion['emailaddress'][0]
        )
        self.assertEqual(
            userdata_from_saml_assertion(fake_saml_assertion, 'first_name', config=reloaded_config),
            fake_saml_assertion['customMyClientFirstName'][0]
        )
        self.assertEqual(
            userdata_from_saml_assertion(fake_saml_assertion, 'last_name', config=reloaded_config),
            fake_saml_assertion['LastName']
        )


class SamlServer(Server):
    def __int__(self, kwargs):
        super(SamlServer, self).__init__(**kwargs)

    def create_authn_response(self, identity, in_response_to, destination,
                              sp_entity_id, name_id_policy=None, userid=None,
                              name_id=None, authn=None, issuer=None,
                              sign_response=None, sign_assertion=None,
                              encrypt_cert_advice=None,
                              encrypt_cert_assertion=None,
                              encrypt_assertion=None,
                              encrypt_assertion_self_contained=True,
                              encrypted_advice_attributes=False, pefim=False,
                              sign_alg=None, digest_alg=None,
                              session_not_on_or_after=None,
                              **kwargs):
        """ Constructs an AuthenticationResponse

        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sp_entity_id: The entity identifier of the Service Provider
        :param name_id_policy: How the NameID should be constructed
        :param userid: The subject identifier
        :param name_id: The identifier of the subject. A saml.NameID instance.
        :param authn: Dictionary with information about the authentication
            context
        :param issuer: Issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not.
        :param sign_response: Whether the response should be signed or not.
        :param encrypt_assertion: True if assertions should be encrypted.
        :param encrypt_assertion_self_contained: True if all encrypted
        assertions should have alla namespaces
        selfcontained.
        :param encrypted_advice_attributes: True if assertions in the advice
        element should be encrypted.
        :param encrypt_cert_advice: Certificate to be used for encryption of
        assertions in the advice element.
        :param encrypt_cert_assertion: Certificate to be used for encryption
        of assertions.
        :param sign_assertion: True if assertions should be signed.
        :param pefim: True if a response according to the PEFIM profile
        should be created.
        :return: A response instance
        """

        try:
            args = self.gather_authn_response_args(
                sp_entity_id, name_id_policy=name_id_policy, userid=userid,
                name_id=name_id, sign_response=sign_response,
                sign_assertion=sign_assertion,
                encrypt_cert_advice=encrypt_cert_advice,
                encrypt_cert_assertion=encrypt_cert_assertion,
                encrypt_assertion=encrypt_assertion,
                encrypt_assertion_self_contained
                =encrypt_assertion_self_contained,
                encrypted_advice_attributes=encrypted_advice_attributes,
                pefim=pefim, **kwargs)

            # authn statement is not returned from gather_authn_response_args()
            # make sure to include it in args if it was passed in initially
            if 'authn_statement' in kwargs:
                args['authn_statement'] = kwargs['authn_statement']
        except IOError as exc:
            response = self.create_error_response(in_response_to,
                                                  destination,
                                                  sp_entity_id,
                                                  exc, name_id)
            return ("%s" % response).split("\n")

        try:
            _authn = authn
            if (sign_assertion or sign_response) and \
                    self.sec.cert_handler.generate_cert():
                with self.lock:
                    self.sec.cert_handler.update_cert(True)
                    return self._authn_response(
                        in_response_to, destination, sp_entity_id, identity,
                        authn=_authn, issuer=issuer, pefim=pefim,
                        sign_alg=sign_alg, digest_alg=digest_alg,
                        session_not_on_or_after=session_not_on_or_after, **args)
            return self._authn_response(
                in_response_to, destination, sp_entity_id, identity,
                authn=_authn, issuer=issuer, pefim=pefim, sign_alg=sign_alg,
                digest_alg=digest_alg,
                session_not_on_or_after=session_not_on_or_after, **args)

        except MissingValue as exc:
            return self.create_error_response(in_response_to, destination,
                                              sp_entity_id, exc, name_id)
