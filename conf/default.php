<?php

/**
 * Configuration defaults for SAML Auth
*/

$conf['idPEntityID'] = 'set me';
$conf['endpoint']  = '';
$conf['slo_endpoint']  = '';
$conf['certificate'] = '';
$conf['lowercase'] = 1;
$conf['autoprovisioning'] = 1;
$conf['use_slo'] = 0;
$conf["auto_login"] = "never";
$conf['sign_requests'] = 0;
$conf['want_assertions_signed'] = 0;
$conf['want_encrypted'] = 0;
$conf['userid_attr_name'] = 'login uid eduPersonPrincipalName';
$conf['fullname_attr_name'] = 'fullname displayName';
$conf['email_attr_name'] = 'email mail';
$conf['groups_attr_name'] = 'groups eduPersonAffiliation';
