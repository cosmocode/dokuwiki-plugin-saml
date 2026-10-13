<?php
/**
 * texts for SAML Auth
 */

$lang['menu']  = 'SAML Configuration Helper';
$lang['login'] = 'Log in with SAML';

$lang['err_unsolicited'] = 'SAML: this wiki did not ask for this login. Logins that start at the identity provider are turned off.';
$lang['err_replay']      = 'SAML: this login was used already. Please start the login again.';

$lang['key_metadata']    = 'The SP metadata of this wiki';
$lang['key_expiry']      = 'The certificate of this wiki is valid until';
$lang['key_manage']      = 'Key of this wiki';
$lang['key_rotate']      = 'Create a new key';
$lang['key_confirm']     = 'Yes, I know that the Identity Provider needs the new certificate at once';
$lang['key_needconfirm'] = 'The new key was not created: please confirm first.';
$lang['key_new']         = 'The wiki created a new key. Give the new certificate to your Identity Provider.';
