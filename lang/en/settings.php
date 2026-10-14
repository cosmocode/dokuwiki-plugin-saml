<?php

/**
 * Configuration texts for SAML Auth
 */

$lang['idPEntityID'] = 'The EntityID of your SAML server. Look for <code>entityID=</code> in the IdP metadata. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['endpoint'] = 'The address of the Single Sign-On service of the IdP (HTTP-Redirect binding only). Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['slo_endpoint'] = '(optional) The address of the Single Logout service of the IdP. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['certificate'] = 'The signing certificates of the IdP as PEM blocks, each between a <code>-----BEGIN CERTIFICATE-----</code> and an <code>-----END CERTIFICATE-----</code> line. The wiki accepts a signature of every certificate here, so you can add the new one before the IdP changes its key. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['lowercase'] = 'Make user and group names lower case? (recommended)';
$lang['autoprovisioning'] = 'Create a user in the wiki at the first login? Otherwise only pre-created users are accepted.';
$lang['use_slo'] = 'Send the user to the IdP for a Single Logout at logout? Most IdP support this poorly, if at all.';
$lang['auto_login'] = 'When to log the user in automatically? <code>never</code> does not; <code>after login</code> does for a user who did not log out; <code>always</code> does for everybody.';
$lang['allow_unsolicited'] = 'Accept a login that starts at the IdP instead of at the wiki? <b>Turn this off only when the IdP is on the domain of the wiki.</b> For another domain the browser does not send the session cookie of the wiki with the response, so the wiki cannot see its own request and refuses every login.';
$lang['sign_requests'] = 'Sign the messages that the wiki sends to the IdP? The IdP needs the certificate of the wiki for this. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['want_assertions_signed'] = 'Require a signature of the assertion itself? The wiki always refuses a response without any signature. Keycloak signs the response by default, ADFS signs the assertion.';
$lang['want_encrypted'] = 'Require an encrypted assertion? <code>RSA-OAEP-MGF1P</code> is the only supported key transport.';
$lang['userid_attr_name'] = 'User login name attribute. With several names, separated by spaces, the first attribute with a value counts.';
$lang['fullname_attr_name'] = 'Full name attribute. With several names, separated by spaces, the values are joined by a space.';
$lang['email_attr_name'] = 'E-mail attribute. With several names, separated by spaces, the first attribute with a value counts.';
$lang['groups_attr_name'] = 'Groups attribute. With several names, separated by spaces, the groups of all attributes are collected.';
