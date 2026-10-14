<?php
/**
 * texts for SAML Auth
 */

$lang['menu']  = 'SAML Configuration Helper';
$lang['login'] = 'Log in with SAML';

$lang['err_unsolicited'] = 'SAML: this wiki did not ask for this login. Please start the login at the wiki.';
$lang['err_replay']      = 'SAML: this login was used already. Please start the login again.';
$lang['err_url']         = 'Can\'t use the address %s. Give a complete address that starts with http:// or https://.';
$lang['err_download']    = 'Failed to download the metadata. %s';
$lang['err_parse']       = 'Failed to parse the metadata. %s';
$lang['err_binding']     = 'The identity provider gives the address %s for a binding other than HTTP-Redirect. The wiki speaks HTTP-Redirect only and does not use that address.';

$lang['meta_manage'] = 'IdP Metadata';
$lang['meta_url']    = 'Metadata URL';
$lang['meta_xml']    = 'Copy/Paste XML Metadata';
$lang['meta_submit'] = 'Submit';

$lang['cmp_setting'] = 'Setting';
$lang['cmp_current'] = 'In the wiki now';
$lang['cmp_found']   = 'In the metadata';

$lang['apply']             = 'Write these values into the configuration';
$lang['apply_manage']      = 'Configuration of the identity provider';
$lang['apply_confirm']     = 'Yes, replace the plugin settings with the metadata values above';
$lang['apply_needconfirm'] = 'No settings changed: please confirm first.';
$lang['apply_noconfig']    = 'Can\'t change settings: the Configuration Manager plugin is disabled.';
$lang['apply_protected']   = 'Can\'t change these settings, they are protected: %s';
$lang['apply_locked']      = 'Failed to change a setting: the configuration is locked.';
$lang['apply_error']       = 'Failed to write the configuration.';
$lang['apply_done']        = 'Settings updated.';

$lang['key_metadata']    = 'The SP metadata of this wiki';
$lang['key_expiry']      = 'The certificate of this wiki is valid until';
$lang['key_manage']      = 'Certification Key Rotation';
$lang['key_rotate']      = 'Create a new key';
$lang['key_confirm']     = 'I understand that no login works until the IdP has the new certificate.';
$lang['key_confirm_unused'] = 'I understand that the IdP needs the new certificate for signed messages and for encryption.';
$lang['key_needconfirm'] = 'The new key was not created: please confirm first.';
$lang['key_new']         = 'New key created. Give the new certificate to your Identity Provider.';
