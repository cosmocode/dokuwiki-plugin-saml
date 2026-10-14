<?php

/**
 * Configuration texts for SAML Auth
 */

$lang['idPEntityID'] = 'The EntityID of your SAML server. Look for <code>entityID=</code> in the IdP metadata. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['endpoint'] = 'The address of the Single Sign-On service of the IdP (HTTP-Redirect binding only). Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['slo_endpoint'] = '(optional) The address of the Single Logout service of the IdP. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['certificate'] = 'The signing certificates of the IdP as PEM blocks, each between a <code>-----BEGIN CERTIFICATE-----</code> and an <code>-----END CERTIFICATE-----</code> line. The wiki accepts a signature of every certificate here, so you can add the new one before the IdP changes its key. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';
$lang['sign_requests'] = 'Sign the messages that the wiki sends to the IdP. The IdP needs the certificate of the wiki for this. Use the <a href="?do=admin&amp;page=saml">SAML Configuration Helper</a> to set this.';

$lang['want_encrypted'] = 'Request encrypted assertions from the IdP. <code>RSA-OAEP-MGF1P</code> is the only key transport supported.';

$lang['auto_login'] = 'Log the user in automatically. <code>never</code> does not; <code>after login</code> does for a user who did not log out; <code>always</code> does for everybody.';
$lang['use_slo'] = 'Automatically log out the user at the IdP on logout. Requires a SLO endpoint above.';
$lang['lowercase'] = 'Make user and group names lower case. (recommended)';
$lang['autoprovisioning'] = 'Create a user in the wiki at the first login. Otherwise only pre-created users can log in.';

$lang['userid_attr_name'] = 'User login name attribute. With several names, separated by spaces, the first attribute with a value counts.';
$lang['fullname_attr_name'] = 'Full name attribute. With several names, separated by spaces, the values are joined by a space.';
$lang['email_attr_name'] = 'E-mail attribute. With several names, separated by spaces, the first attribute with a value counts.';
$lang['groups_attr_name'] = 'Groups attribute. With several names, separated by spaces, the groups of all attributes are collected.';
