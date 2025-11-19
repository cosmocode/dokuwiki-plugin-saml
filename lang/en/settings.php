<?php
/**
 * Configuration texts for SAML Auth
 */

$lang['idPEntityID'] = <<<ENDDOC
The EntityID of your SAML server. Look for <code>entityID=</code> in the IDP
metadata. Examples:
<ul>
<li><code>https://adfs.example.org/adfs/services/trust</code>
<li><code>https://idp.example.edu/idp/shibboleth</code>
</ul>
ENDDOC;

$lang['endpoint'] = <<<ENDDOC
The SAML auth API endpoint, a.k.a. the HTTP-Redirect Binding.
Examples:
<ul>
<li><code>https://adfs.example.org/adfs/ls/</code>
<li><code>https://idp.example.edu/idp/profile/SAML2/Redirect/SSO</code>
</ul>
Note: do not use the <code>POST</code> binding
ENDDOC;


$lang['slo_endpoint'] = <<<ENDDOC
(optional) The SAML auth API endpoint for the Single Logout service. Most IdP
support this poorly, if at all.
Examples:
<ul>
<li><code>https://adfs.example.org/adfs/ls/</code>
</ul>
ENDDOC;

$lang['certificate'] = <<<ENDDOC
The SAML IDP signing certificate. Look for the certificate under the
<code>&lt;KeyDescriptor use="signing"&gt;</code> element of the IDP metadata
XML. It will be a long string of text starting with <code>MII</code>...
ENDDOC;

$lang['lowercase'] = <<<ENDDOC
Treat user and group names as case-insensitive and lower case them
automatically? (recommended)
ENDDOC;

$lang['autoprovisioning'] = <<<ENDDOC
Automatic user provisioning: authenticated users are created automatically and
do not need to be added manually by the wiki administrator
ENDDOC;

$lang['use_slo'] = <<<ENDDOC
Should users be redirected back to the IDP to complete a Single Logoff if they click the DokuWiki logout?
(not recommended, unless your IdP actually supports SLO)
ENDDOC;

$lang["auto_login"] = <<<ENDDOC
When to enforce auto-login?
<ul>
<li><code>never</code> will never ask to automatically authenticate;
<li><code>after login</code> will prompt to automatically ask to re-authenticate if
the DokuWiki session ends unless explicitly logged out;
<li><code>always</code> will always require login
</ul>
ENDDOC;

$lang['userid_attr_name'] = <<<ENDDOC
Examples:
<ul>
<li><code>login</code> (ADFS);
<li><code>urn:oid:0.9.2342.19200300.100.1.1</code> (Shibboleth uid)
<li><code>urn:oid:1.3.6.1.4.1.5923.1.1.1.6</code> (eduPersonPrincipalName, beware of
<code>@</code> being rewritten to <code>_</code>)
</ul>
ENDDOC;

$lang['fullname_attr_name'] = <<<ENDDOC
Examples:
<ul>
<li><code>fullname</code> (ADFS);
<li><code>urn:oid:2.16.840.1.113730.3.1.241</code> (displayName)
</ul>
ENDDOC;

$lang['email_attr_name'] = <<<ENDDOC
Examples:
<ul>
<li><code>email</code> (ADFS);
<li><code>urn:oid:0.9.2342.19200300.100.1.3</code> (mail)
</ul>
ENDDOC;

$lang['groups_attr_name'] = <<<ENDDOC
Examples:
<ul>
<li><code>groups</code> (ADFS);
<li><code>urn:oid:1.3.6.1.4.1.5923.1.1.1.1</code> (eduPersonAffiliation)
<li><code>urn:oid:2.5.4.11</code> (organizationalUnitName)
</ul>
ENDDOC;