<?php

namespace dokuwiki\plugin\saml\test;

use DOMDocument;
use dokuwiki\plugin\saml\Settings;
use DokuWikiTest;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Base for the tests that send a SAML message to the library
 *
 * Builds and signs the messages that an identity provider would send. The key and the
 * certificate of the test identity provider are in _test/data/.
 *
 * @group plugin_saml
 * @group plugins
 */
abstract class AbstractMessageTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

    /** @var string the entity ID of the test identity provider */
    protected const IDPENTITY = 'https://idp.example.org/';

    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();

        // the library builds the address of this wiki from the base URL and this script
        $_SERVER['SCRIPT_NAME'] = '/' . DOKU_SCRIPT;
        $_SERVER['REQUEST_URI'] = '/' . DOKU_SCRIPT;
        unset($_SERVER['QUERY_STRING']);
        $_POST = [];
        $_GET = [];

        self::seedServiceProviderKey();
    }

    /**
     * Put the key pair of the test service provider in place
     *
     * The key store creates a key pair when it finds none. That takes a moment, so the
     * tests use a key of their own.
     *
     * @return void
     */
    public static function seedServiceProviderKey()
    {
        global $conf;
        io_mkdir_p($conf['metadir']);
        foreach (['.key', '.crt'] as $suffix) {
            copy(__DIR__ . '/data/_saml' . $suffix, $conf['metadir'] . '/_saml' . $suffix);
        }
    }

    /** @inheritdoc */
    public function tearDown(): void
    {
        $_POST = [];
        $_GET = [];
        parent::tearDown();
    }

    /**
     * The key or the certificate of a test identity provider
     *
     * @param string $name key or crt
     * @param string $who idp or other
     * @return string the file content in PEM format
     */
    protected function getPem($name, $who = 'idp')
    {
        return file_get_contents(__DIR__ . '/data/' . $who . '.' . $name);
    }

    /**
     * The plugin configuration that the tests start from
     *
     * @param array $overrides settings that differ from the default
     * @return array
     */
    protected function getConf($overrides = [])
    {
        return array_merge([
            'idPEntityID' => self::IDPENTITY,
            'endpoint' => 'https://idp.example.org/sso',
            'slo_endpoint' => 'https://idp.example.org/slo',
            'certificate' => $this->getPem('crt'),
            'lowercase' => 1,
            'autoprovisioning' => 1,
            'auto_login' => 'never',
            'use_slo' => 0,
            'allow_unsolicited' => 1,
            'sign_requests' => 0,
            'want_assertions_signed' => 0,
            'want_encrypted' => 0,
            'userid_attr_name' => 'login',
            'fullname_attr_name' => 'fullname',
            'email_attr_name' => 'email',
            'groups_attr_name' => 'groups',
        ], $overrides);
    }

    /**
     * The configuration of the plugin before an admin changes anything
     *
     * @return array
     */
    protected function getDefaultConf()
    {
        $conf = [];
        include DOKU_PLUGIN . 'saml/conf/default.php';
        return $conf;
    }

    /**
     * The library, set up like the plugin sets it up
     *
     * @param array $overrides settings that differ from the default
     * @return Auth
     */
    protected function getLib($overrides = [])
    {
        return new Auth((new Settings($this->getConf($overrides)))->toArray());
    }

    /**
     * A response of the identity provider
     *
     * @param array $options destination, audience, issuer, inResponseTo, assertionId,
     *                       notBefore, notOnOrAfter, confirmationExpiry, sessionExpiry,
     *                       sign, signer, encrypt, attributes
     * @return string the message, base64 encoded as the HTTP POST binding wants it
     */
    protected function getResponse($options = [])
    {
        $options = array_merge([
            'destination' => DOKU_URL . DOKU_SCRIPT,
            'audience' => DOKU_URL,
            'issuer' => self::IDPENTITY,
            'inResponseTo' => null,
            'assertionId' => '_assertion' . md5((string)microtime(true)),
            'notBefore' => time() - 60,
            'notOnOrAfter' => time() + 300,
            'confirmationExpiry' => 'as the assertion', // null omits the attribute
            'sessionExpiry' => time() + 3600,
            'sign' => true,
            'signer' => 'idp',
            'encrypt' => false,
            'attributes' => [
                'login' => ['andi'],
                'fullname' => ['Andreas Gohr'],
                'email' => ['andi@example.org'],
                'groups' => ['admins'],
            ],
        ], $options);

        $xml = $this->buildResponse($options);
        if ($options['encrypt']) {
            $xml = $this->encryptAssertion($xml);
        }
        if ($options['sign']) {
            $xml = Utils::addSign(
                $xml,
                $this->getPem('key', $options['signer']),
                $this->getPem('crt', $options['signer'])
            );
        }

        return base64_encode($xml);
    }

    /**
     * A logout message of the identity provider
     *
     * @param array $options nameId, sessionIndex, destination, issuer, inResponseTo,
     *                       status, sign
     * @return string the message, base64 encoded
     */
    protected function getLogoutMessage($options = [])
    {
        $options = array_merge([
            'nameId' => 'andi',
            'sessionIndex' => '_session1',
            'destination' => DOKU_URL . DOKU_SCRIPT . '?do=saml_sls',
            'issuer' => self::IDPENTITY,
            'inResponseTo' => '', // a LogoutResponse when it is set
            'status' => Constants::STATUS_SUCCESS,
            'sign' => true,
        ], $options);

        $time = gmdate('Y-m-d\TH:i:s\Z', time());
        $head = ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' .
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' .
            ' ID="_message' . md5((string)microtime(true)) . '" Version="2.0"' .
            ' IssueInstant="' . $time . '"' .
            ' Destination="' . hsc($options['destination']) . '"';
        $issuer = '<saml:Issuer>' . hsc($options['issuer']) . '</saml:Issuer>';

        if ($options['inResponseTo'] !== '') {
            $xml = '<samlp:LogoutResponse' . $head .
                ' InResponseTo="' . hsc($options['inResponseTo']) . '">' . $issuer .
                '<samlp:Status><samlp:StatusCode Value="' . hsc($options['status']) . '"/></samlp:Status>' .
                '</samlp:LogoutResponse>';
        } else {
            $index = $options['sessionIndex'] === ''
                ? ''
                : '<samlp:SessionIndex>' . hsc($options['sessionIndex']) . '</samlp:SessionIndex>';
            $xml = '<samlp:LogoutRequest' . $head . '>' . $issuer .
                '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' .
                hsc($options['nameId']) . '</saml:NameID>' . $index .
                '</samlp:LogoutRequest>';
        }

        if ($options['sign']) {
            $xml = Utils::addSign($xml, $this->getPem('key'), $this->getPem('crt'));
        }

        return base64_encode($xml);
    }

    /**
     * Put a logout message of the Redirect binding into the request
     *
     * The signature of that binding travels next to the message, over the query string.
     *
     * @param string $message the base64 message
     * @param bool $isRequest a LogoutRequest, otherwise a LogoutResponse
     * @param bool $sign add the signature of the identity provider
     * @return void
     */
    protected function sendByRedirect($message, $isRequest, $sign = true)
    {
        $name = $isRequest ? 'SAMLRequest' : 'SAMLResponse';
        $deflated = base64_encode(gzdeflate(base64_decode($message)));

        $_GET[$name] = $deflated;
        if (!$sign) return;

        $algorithm = XMLSecurityKey::RSA_SHA256;
        $query = $name . '=' . urlencode($deflated) . '&SigAlg=' . urlencode($algorithm);

        $key = new XMLSecurityKey($algorithm, ['type' => 'private']);
        $key->loadKey($this->getPem('key'), false);

        $_GET['SigAlg'] = $algorithm;
        $_GET['Signature'] = base64_encode($key->signData($query));
    }

    /**
     * Encrypt the assertion of a response for the certificate of this wiki
     *
     * The assertion gets a session key, and that key gets the public key of the wiki.
     * Only the wiki can read the assertion afterwards.
     *
     * @param string $xml the response with a plain assertion
     * @return string the response with an EncryptedAssertion
     */
    protected function encryptAssertion($xml)
    {
        global $conf;

        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $assertion = $doc->getElementsByTagNameNS(Constants::NS_SAML, 'Assertion')->item(0);

        $sessionKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
        $sessionKey->generateSessionKey();

        $wikiKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']);
        $wikiKey->loadKey(io_readFile($conf['metadir'] . '/_saml.crt', false), false, true);

        $enc = new XMLSecEnc();
        $enc->setNode($assertion);
        $enc->type = XMLSecEnc::Element;
        $enc->encryptKey($wikiKey, $sessionKey);
        $encrypted = $enc->encryptNode($sessionKey);

        $wrapper = $doc->createElementNS(Constants::NS_SAML, 'saml:EncryptedAssertion');
        $encrypted->parentNode->replaceChild($wrapper, $encrypted);
        $wrapper->appendChild($encrypted);

        return $doc->saveXML();
    }

    /**
     * The XML of a response of the identity provider
     *
     * @param array $options see getResponse()
     * @return string
     */
    protected function buildResponse($options)
    {
        $time = static fn($stamp) => gmdate('Y-m-d\TH:i:s\Z', $stamp);

        $inResponseTo = $options['inResponseTo']
            ? ' InResponseTo="' . hsc($options['inResponseTo']) . '"'
            : '';

        $confirmationExpiry = $options['confirmationExpiry'] === 'as the assertion'
            ? $options['notOnOrAfter']
            : $options['confirmationExpiry'];
        $confirmationExpiry = $confirmationExpiry
            ? ' NotOnOrAfter="' . $time($confirmationExpiry) . '"'
            : '';

        $attributes = '';
        foreach ($options['attributes'] as $name => $values) {
            $attributes .= '<saml:Attribute Name="' . hsc($name) .
                '" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">';
            foreach ($values as $value) {
                $attributes .= '<saml:AttributeValue>' . hsc($value) . '</saml:AttributeValue>';
            }
            $attributes .= '</saml:Attribute>';
        }

        return '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' .
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' .
            ' ID="_response' . md5($options['assertionId']) . '" Version="2.0"' .
            ' IssueInstant="' . $time(time()) . '"' .
            ' Destination="' . hsc($options['destination']) . '"' . $inResponseTo . '>' .
            '<saml:Issuer>' . hsc($options['issuer']) . '</saml:Issuer>' .
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' .
            // the namespace is declared here as well, an assertion may travel encrypted
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' .
            ' ID="' . hsc($options['assertionId']) . '" Version="2.0"' .
            ' IssueInstant="' . $time(time()) . '">' .
            '<saml:Issuer>' . hsc($options['issuer']) . '</saml:Issuer>' .
            '<saml:Subject>' .
            '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">andi</saml:NameID>' .
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' .
            '<saml:SubjectConfirmationData' . $confirmationExpiry .
            ' Recipient="' . hsc($options['destination']) . '"' . $inResponseTo . '/>' .
            '</saml:SubjectConfirmation>' .
            '</saml:Subject>' .
            '<saml:Conditions NotBefore="' . $time($options['notBefore']) . '"' .
            ' NotOnOrAfter="' . $time($options['notOnOrAfter']) . '">' .
            '<saml:AudienceRestriction>' .
            '<saml:Audience>' . hsc($options['audience']) . '</saml:Audience>' .
            '</saml:AudienceRestriction>' .
            '</saml:Conditions>' .
            '<saml:AuthnStatement AuthnInstant="' . $time(time()) . '" SessionIndex="_session1"' .
            ' SessionNotOnOrAfter="' . $time($options['sessionExpiry']) . '">' .
            '<saml:AuthnContext><saml:AuthnContextClassRef>' .
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' .
            '</saml:AuthnContextClassRef></saml:AuthnContext>' .
            '</saml:AuthnStatement>' .
            '<saml:AttributeStatement>' . $attributes . '</saml:AttributeStatement>' .
            '</saml:Assertion>' .
            '</samlp:Response>';
    }
}
