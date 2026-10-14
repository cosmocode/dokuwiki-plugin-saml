<?php

/**
 * Configuration defaults for SAML Auth
*/

// the identity provider, the SAML Configuration Helper reads these from its metadata
$conf['idPEntityID'] = 'set me';
$conf['endpoint']  = '';
$conf['slo_endpoint']  = '';
$conf['certificate'] = '';
$conf['sign_requests'] = 0;

// what the wiki demands of the identity provider
$conf['want_encrypted'] = 0;

// how the wiki logs a user in and out
$conf["auto_login"] = "never";
$conf['use_slo'] = 1;
$conf['lowercase'] = 1;
$conf['autoprovisioning'] = 1;

// the attributes that carry the user data
$conf['userid_attr_name'] = 'login uid eduPersonPrincipalName';
$conf['fullname_attr_name'] = 'fullname displayName';
$conf['email_attr_name'] = 'email mail';
$conf['groups_attr_name'] = 'groups eduPersonAffiliation';
