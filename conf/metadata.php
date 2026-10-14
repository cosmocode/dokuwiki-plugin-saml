<?php

/**
 * Configuration metadata for SAML Auth
*/

// the identity provider, the SAML Configuration Helper reads these from its metadata
$meta['idPEntityID'] = array('string');
$meta['endpoint']    = array('string');
$meta['slo_endpoint']    = array('string');
$meta['certificate'] = array('');
$meta['sign_requests'] = array('onoff');

// what the wiki demands of the identity provider
$meta['want_encrypted'] = array('onoff');

// how the wiki logs a user in and out
$meta["auto_login"] = array('multichoice','_choices' => array('never','after login','always'));
$meta['use_slo']   = array('onoff');
$meta['lowercase']   = array('onoff');
$meta['autoprovisioning'] = array('onoff');

// the attributes that carry the user data
$meta['userid_attr_name'] = array('string');
$meta['fullname_attr_name'] = array('string');
$meta['email_attr_name'] = array('string');
$meta['groups_attr_name'] = array('string');
