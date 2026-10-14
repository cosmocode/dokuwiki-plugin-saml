<?php

/**
 * Configuration metadata for SAML Auth
*/

$meta['idPEntityID'] = array('string');
$meta['endpoint']    = array('string');
$meta['slo_endpoint']    = array('string');
$meta['certificate'] = array('');
$meta['lowercase']   = array('onoff');
$meta['autoprovisioning'] = array('onoff');
$meta['use_slo']   = array('onoff');
$meta["auto_login"] = array('multichoice','_choices' => array('never','after login','always'));
$meta['sign_requests'] = array('onoff');
$meta['want_assertions_signed'] = array('onoff');
$meta['want_encrypted'] = array('onoff');
$meta['userid_attr_name'] = array('string');
$meta['fullname_attr_name'] = array('string');
$meta['email_attr_name'] = array('string');
$meta['groups_attr_name'] = array('string');
