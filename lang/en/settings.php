<?php

/**
 * Configuration texts for SAML Auth
 */

$lang['idPEntityID'] = 'The EntityID of your SAML server. Look for <code>entityID=</code> in the IDP metadata. Examples: <code>https://adfs.example.org/adfs/services/trust</code>, <code>https://idp.example.edu/idp/shibboleth</code>';
$lang['endpoint'] = 'The SAML auth API endpoint, a.k.a. the HTTP-Redirect Binding. Examples: <code>https://adfs.example.org/adfs/ls/</code>, <code>https://idp.example.edu/idp/profile/SAML2/Redirect/SSO</code>. Do not use the <code>POST</code> binding.';
$lang['slo_endpoint'] = '(optional) The SAML auth API endpoint for the Single Logout service. Most IdP support this poorly, if at all. Example: <code>https://adfs.example.org/adfs/ls/</code>';
$lang['certificate'] = 'The SAML IDP signing certificate. Look for the certificate under the <code>&lt;KeyDescriptor use="signing"&gt;</code> element of the IDP metadata XML. It will be a long string of text starting with <code>MII</code>...';
$lang['lowercase'] = 'Treat user and group names as case-insensitive and lower case them automatically? (recommended)';
$lang['autoprovisioning'] = 'Automatic user provisioning: authenticated users are created automatically and do not need to be added manually by the wiki administrator';
$lang['use_slo'] = 'Should users be redirected back to the IDP to complete a Single Logoff if they click the DokuWiki logout? (not recommended, unless your IdP actually supports SLO)';
$lang['auto_login'] = 'When to enforce auto-login? <code>never</code> will never ask to automatically authenticate; <code>after login</code> will prompt to automatically ask to re-authenticate if the DokuWiki session ends unless explicitly logged out; <code>always</code> will always require login';
$lang['allow_unsolicited'] = 'Accept a login that starts at the Identity Provider instead of at the wiki? <b>Only turn this off when the Identity Provider is on the same domain as the wiki.</b> For a provider on another domain the browser does not send the session cookie of the wiki together with the response, so the wiki cannot see its own request and refuses every login.';
$lang['userid_attr_name'] = 'User login name attribute. Examples: <code>login</code> (ADFS), <code>urn:oid:0.9.2342.19200300.100.1.1</code> (Shibboleth uid), <code>urn:oid:1.3.6.1.4.1.5923.1.1.1.6</code> (eduPersonPrincipalName, beware of <code>@</code> being rewritten to <code>_</code>)';
$lang['fullname_attr_name'] = 'Full name attribute. Examples: <code>fullname</code> (ADFS), <code>urn:oid:2.16.840.1.113730.3.1.241</code> (displayName)';
$lang['email_attr_name'] = 'E-mail attribute. Examples: <code>email</code> (ADFS), <code>urn:oid:0.9.2342.19200300.100.1.3</code> (mail)';
$lang['groups_attr_name'] = 'Groups attribute. Examples: <code>groups</code> (ADFS), <code>urn:oid:1.3.6.1.4.1.5923.1.1.1.1</code> (eduPersonAffiliation), <code>urn:oid:2.5.4.11</code> (organizationalUnitName)';
