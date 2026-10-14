<?php

namespace dokuwiki\plugin\saml\test;

use DOMDocument;
use dokuwiki\plugin\saml\KeyStore;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Tests for the SP metadata that describes this wiki
 *
 * @group plugin_saml
 * @group plugins
 */
class MetadataTest extends AbstractMessageTest
{
    /**
     * The metadata of the plugin, built as the wiki sends it
     *
     * @param array $overrides settings that differ from the default
     * @return string
     */
    protected function getMetadata($overrides = [])
    {
        global $conf;
        $conf['plugin']['saml'] = $this->getConf($overrides);

        /** @var \helper_plugin_saml $hlp */
        $hlp = plugin_load('helper', 'saml', true);
        return $hlp->getMetadata();
    }

    /**
     * A wiki without a configured identity provider still describes itself
     *
     * The identity provider may create its client from this file, so the wiki has to
     * send it before an admin can fill in the settings of the identity provider.
     */
    public function testWithoutConfiguration()
    {
        $xml = $this->getMetadata($this->getDefaultConf());

        $this->assertEquals([], $this->getLib()->getSettings()->validateMetadata($xml));
        $this->assertStringContainsString('entityID="' . DOKU_URL . '"', $xml);
        $this->assertStringContainsString('<ds:Signature', $xml);
    }

    /**
     * The metadata is valid and describes this wiki
     */
    public function testMetadata()
    {
        $xml = $this->getMetadata();

        $this->assertEquals([], $this->getLib()->getSettings()->validateMetadata($xml));
        $this->assertStringContainsString('entityID="' . DOKU_URL . '"', $xml);
        $this->assertStringContainsString(DOKU_URL . DOKU_SCRIPT, $xml);
    }

    /**
     * The metadata carries the signature of this wiki
     */
    public function testSigned()
    {
        $xml = $this->getMetadata();

        $this->assertStringContainsString('<ds:Signature', $xml);
        $this->assertStringContainsString('rsa-sha256', $xml);
    }

    /**
     * The metadata tells how long it may be kept, but it does not expire
     *
     * An admin of an isolated wiki uploads this file by hand once. A validUntil would
     * make that copy invalid after two days.
     */
    public function testNoExpiry()
    {
        $xml = $this->getMetadata();

        $this->assertStringContainsString('cacheDuration=', $xml);
        $this->assertStringNotContainsString('validUntil=', $xml);
    }

    /**
     * The certificate of the wiki is published for its signature
     */
    public function testCertificates()
    {
        global $conf;
        $xml = $this->getMetadata();
        $certificate = trim(preg_replace(
            '/-----[A-Z ]+-----/',
            '',
            io_readFile($conf['metadir'] . '/_saml.crt', false)
        ));

        $this->assertEquals(1, substr_count($xml, 'use="signing"'));
        $this->assertStringContainsString(substr($certificate, 0, 60), $xml);
    }

    /**
     * The certificate for encryption travels only when the wiki wants an encrypted assertion
     *
     * An identity provider builds its client from this file. A certificate that the wiki
     * publishes without need invites an encryption that the admin never asked for.
     */
    public function testEncryptionCertificate()
    {
        $this->assertEquals(0, substr_count($this->getMetadata(), 'use="encryption"'));
        $this->assertEquals(1, substr_count($this->getMetadata(['want_encrypted' => 1]), 'use="encryption"'));
    }

    /**
     * The metadata names the key transport that the wiki can read
     *
     * xmlseclibs reads RSA-OAEP with the digest SHA-1 only. Without this element an
     * identity provider picks its own standard and the wiki cannot read the assertion.
     */
    public function testEncryptionMethod()
    {
        $doc = new DOMDocument();
        $doc->loadXML($this->getMetadata(['want_encrypted' => 1]));

        $methods = $doc->getElementsByTagNameNS(Constants::NS_MD, 'EncryptionMethod');

        $this->assertEquals(1, $methods->length);
        $this->assertEquals(XMLSecurityKey::RSA_OAEP_MGF1P, $methods->item(0)->getAttribute('Algorithm'));
        $this->assertEquals('KeyDescriptor', $methods->item(0)->parentNode->localName);
        $this->assertEquals('encryption', $methods->item(0)->parentNode->getAttribute('use'));
    }

    /**
     * The signature of the metadata covers what the plugin added to it
     */
    public function testSignatureIsValid()
    {
        global $conf;
        $certificate = io_readFile($conf['metadir'] . '/_saml.crt', false);

        foreach ([0, 1] as $encrypted) {
            $xml = $this->getMetadata(['want_encrypted' => $encrypted]);
            $this->assertTrue(
                Utils::validateSign($xml, $certificate, null, 'sha256', '//md:EntityDescriptor/ds:Signature'),
                'the signature of the metadata is not valid'
            );
        }
    }

    /**
     * A new key replaces the certificate in the metadata, it does not add one
     *
     * The wiki keeps one private key. A second certificate would invite the identity
     * provider to encrypt an assertion for a key that the wiki no longer has.
     */
    public function testOneCertificateOnly()
    {
        $this->getMetadata();
        (new KeyStore())->rotate();

        $xml = $this->getMetadata(['want_encrypted' => 1]);

        $this->assertEquals(1, substr_count($xml, 'use="signing"'));
        $this->assertEquals(1, substr_count($xml, 'use="encryption"'));
    }

    /**
     * The metadata announces the Single Logout Service of the wiki
     */
    public function testLogoutService()
    {
        $doc = new DOMDocument();
        $doc->loadXML($this->getMetadata());

        $services = $doc->getElementsByTagNameNS(Constants::NS_MD, 'SingleLogoutService');

        $this->assertEquals(1, $services->length);
        $this->assertEquals(Constants::BINDING_HTTP_REDIRECT, $services->item(0)->getAttribute('Binding'));
        $this->assertEquals(
            DOKU_URL . DOKU_SCRIPT . '?do=saml_sls',
            $services->item(0)->getAttribute('Location')
        );
    }

    /**
     * The metadata tells the identity provider whether the wiki signs its requests
     */
    public function testSignedRequestsAnnounced()
    {
        $this->assertStringContainsString(
            'AuthnRequestsSigned="false"',
            $this->getMetadata()
        );
        $this->assertStringContainsString(
            'AuthnRequestsSigned="true"',
            $this->getMetadata(['sign_requests' => 1])
        );
    }

    /**
     * The private key of the wiki is never part of the metadata
     */
    public function testNoPrivateKey()
    {
        $xml = $this->getMetadata();

        $this->assertStringNotContainsString('PRIVATE KEY', $xml);
    }
}
