<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\Settings;
use DokuWikiTest;
use OneLogin\Saml2\Auth;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Tests for the settings of the php-saml library
 *
 * @group plugin_saml
 * @group plugins
 */
class SettingsTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();
        AbstractMessageTest::seedServiceProviderKey();
    }

    /** @var string the base64 part of a certificate, longer than one line */
    protected const CERTBODY = 'MIIBCgKCAQEAwJ6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z3Z6Z';

    /**
     * A certificate body in PEM format
     *
     * @param string $body the base64 body
     * @return string
     */
    protected function getPem($body)
    {
        return "-----BEGIN CERTIFICATE-----\n" .
            wordwrap($body, 64, "\n", true) .
            "\n-----END CERTIFICATE-----\n";
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
            'idPEntityID' => 'https://idp.example.org/',
            'endpoint' => 'https://idp.example.org/sso',
            'slo_endpoint' => 'https://idp.example.org/slo',
            'certificate' => self::CERTBODY,
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
     * A bare certificate body gives one signing certificate
     */
    public function testBareCertificate()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertEquals([self::CERTBODY], $settings['idp']['x509certMulti']['signing']);
    }

    /**
     * A certificate in PEM format gives the same value as its bare body
     */
    public function testPemCertificate()
    {
        $settings = (new Settings($this->getConf(['certificate' => $this->getPem(self::CERTBODY)])))->toArray();

        $this->assertEquals([self::CERTBODY], $settings['idp']['x509certMulti']['signing']);
    }

    /**
     * Every PEM block gives a signing certificate
     */
    public function testTwoCertificates()
    {
        $other = strtr(self::CERTBODY, ['Z' => 'Y']);
        $config = $this->getPem(self::CERTBODY) . "\n" . $this->getPem($other);
        $settings = (new Settings($this->getConf(['certificate' => $config])))->toArray();

        $this->assertEquals([self::CERTBODY, $other], $settings['idp']['x509certMulti']['signing']);
    }

    /**
     * A configuration without a certificate gives none
     */
    public function testNoCertificate()
    {
        $settings = (new Settings($this->getConf(['certificate' => ''])))->toArray();

        $this->assertEquals([], $settings['idp']['x509certMulti']['signing']);
    }

    /**
     * The service provider describes this wiki
     *
     * It asks for no attributes: an empty AttributeConsumingService is not valid against
     * the metadata schema.
     */
    public function testServiceProvider()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertEquals(DOKU_URL, $settings['sp']['entityId']);
        $this->assertEquals(DOKU_URL . DOKU_SCRIPT, $settings['sp']['assertionConsumerService']['url']);
        $this->assertArrayNotHasKey('attributeConsumingService', $settings['sp']);
    }

    /**
     * The identity provider is taken from the configuration
     */
    public function testIdentityProvider()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertEquals('https://idp.example.org/', $settings['idp']['entityId']);
        $this->assertEquals('https://idp.example.org/sso', $settings['idp']['singleSignOnService']['url']);
        $this->assertEquals('https://idp.example.org/slo', $settings['idp']['singleLogoutService']['url']);
    }

    /**
     * The library checks the response as strictly as the plugin needs it
     */
    public function testSecurity()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertTrue($settings['strict']);
        $this->assertTrue($settings['security']['destinationStrictlyMatches']);
        $this->assertFalse($settings['security']['rejectUnsolicitedResponsesWithInResponseTo']);
        $this->assertFalse($settings['security']['requestedAuthnContext']);
    }

    /**
     * The wiki signs with SHA-256
     */
    public function testSignatureAlgorithm()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertEquals(XMLSecurityKey::RSA_SHA256, $settings['security']['signatureAlgorithm']);
        $this->assertEquals(XMLSecurityDSig::SHA256, $settings['security']['digestAlgorithm']);
    }

    /**
     * The wiki publishes one certificate only, the one whose key it has
     */
    public function testOneCertificate()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertArrayNotHasKey('x509certNew', $settings['sp']);
    }

    /**
     * The key pair of the wiki is part of the settings, the key is never public
     */
    public function testKeyPair()
    {
        $settings = (new Settings($this->getConf()))->toArray();

        $this->assertStringContainsString('PRIVATE KEY', $settings['sp']['privateKey']);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $settings['sp']['x509cert']);
        $this->assertTrue(openssl_x509_check_private_key($settings['sp']['x509cert'], $settings['sp']['privateKey']));
    }

    /**
     * The wiki signs its request only when the admin asks for it
     */
    public function testSignedRequest()
    {
        $auth = new Auth((new Settings($this->getConf(['sign_requests' => 1])))->toArray());
        $url = $auth->login(null, [], false, false, true, false);
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

        $this->assertArrayHasKey('Signature', $query);
        $this->assertEquals(XMLSecurityKey::RSA_SHA256, $query['SigAlg']);
    }

    /**
     * Without the setting the request carries no signature
     */
    public function testUnsignedRequest()
    {
        $auth = new Auth((new Settings($this->getConf()))->toArray());
        $url = $auth->login(null, [], false, false, true, false);
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

        $this->assertArrayNotHasKey('Signature', $query);
    }

    /**
     * The metadata of this service provider is valid
     */
    public function testMetadata()
    {
        $auth = new Auth((new Settings($this->getConf()))->toArray());
        $xml = $auth->getSettings()->getSPMetadata();

        $this->assertEquals([], $auth->getSettings()->validateMetadata($xml));
    }

    /**
     * The request to the identity provider has no NameIDPolicy and no RequestedAuthnContext
     */
    public function testAuthnRequest()
    {
        $auth = new Auth((new Settings($this->getConf()))->toArray());
        $url = $auth->login(null, [], false, false, true, false);

        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
        $request = gzinflate(base64_decode($query['SAMLRequest']));

        $this->assertStringStartsWith('https://idp.example.org/sso', $url);
        $this->assertStringNotContainsString('NameIDPolicy', $request);
        $this->assertStringNotContainsString('RequestedAuthnContext', $request);
    }
}
