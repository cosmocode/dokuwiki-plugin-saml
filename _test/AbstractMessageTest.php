<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\Settings;
use DokuWikiTest;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

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
    }

    /** @inheritdoc */
    public function tearDown(): void
    {
        $_POST = [];
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
            'userid_attr_name' => 'login',
            'fullname_attr_name' => 'fullname',
            'email_attr_name' => 'email',
            'groups_attr_name' => 'groups',
        ], $overrides);
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
     *                       sign, signer, attributes
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
            'attributes' => [
                'login' => ['andi'],
                'fullname' => ['Andreas Gohr'],
                'email' => ['andi@example.org'],
                'groups' => ['admins'],
            ],
        ], $options);

        $xml = $this->buildResponse($options);
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
            '<saml:Assertion ID="' . hsc($options['assertionId']) . '" Version="2.0"' .
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
