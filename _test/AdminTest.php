<?php

namespace dokuwiki\plugin\saml\test;

use admin_plugin_saml;
use dokuwiki\plugin\saml\KeyStore;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;

/**
 * Tests for the admin page of the plugin
 *
 * @group plugin_saml
 * @group plugins
 */
class AdminTest extends AbstractMessageTest
{
    /** @var string the local configuration of the wiki before the test */
    protected $localConf = '';

    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();

        // the core checks the security token for a logged in user only
        global $INPUT;
        $INPUT->server->set('REMOTE_USER', 'tester');

        $this->localConf = (string)@file_get_contents(DOKU_CONF . 'local.php');

        global $MSG;
        $MSG = [];
    }

    /** @inheritdoc */
    public function tearDown(): void
    {
        // the conf directory is set up once for the class, not for each test
        @chmod(DOKU_CONF . 'local.php', 0644);
        file_put_contents(DOKU_CONF . 'local.php', $this->localConf);
        @unlink(DOKU_CONF . 'local.php.bak.php');

        parent::tearDown();
    }

    /**
     * The admin page, ready to use
     *
     * @return admin_plugin_saml
     */
    protected function getAdmin()
    {
        global $conf;
        $conf['plugin']['saml'] = $this->getConf();

        return new admin_plugin_saml();
    }

    /**
     * The metadata of a test identity provider
     *
     * @param array $options ssoBinding, sloBinding, entityId, signers, wantSignedRequests
     * @return string the metadata in XML
     */
    protected function getIdpMetadata($options = [])
    {
        $options = array_merge([
            'entityId' => self::IDPENTITY,
            'ssoBinding' => Constants::BINDING_HTTP_REDIRECT,
            'sloBinding' => Constants::BINDING_HTTP_REDIRECT,
            'signers' => ['idp'],
            'wantSignedRequests' => null, // null leaves the attribute out
        ], $options);

        $wants = $options['wantSignedRequests'] === null
            ? ''
            : ' WantAuthnRequestsSigned="' . $options['wantSignedRequests'] . '"';

        $keys = '';
        foreach ($options['signers'] as $signer) {
            $keys .= '<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>' .
                '<ds:X509Certificate>' . $this->getCertBody($signer) . '</ds:X509Certificate>' .
                '</ds:X509Data></ds:KeyInfo></KeyDescriptor>';
        }

        return '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"' .
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' .
            ' entityID="' . hsc($options['entityId']) . '">' .
            '<IDPSSODescriptor' . $wants .
            ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' .
            $keys .
            '<SingleSignOnService Binding="' . hsc($options['ssoBinding']) . '"' .
            ' Location="https://idp.example.org/sso-from-metadata"/>' .
            '<SingleLogoutService Binding="' . hsc($options['sloBinding']) . '"' .
            ' Location="https://idp.example.org/slo-from-metadata"/>' .
            '</IDPSSODescriptor></EntityDescriptor>';
    }

    /**
     * The base64 body of the certificate of a test identity provider
     *
     * @param string $who idp or other
     * @return string
     */
    protected function getCertBody($who = 'idp')
    {
        return (string)preg_replace('/-----[A-Z ]+-----|\s/', '', $this->getPem('crt', $who));
    }

    /**
     * Give the metadata to the admin page and return what the page shows
     *
     * @param string $xml the metadata
     * @return string the HTML of the page
     */
    protected function showMetadata($xml)
    {
        global $INPUT;
        $INPUT->set('xml', $xml);

        $admin = $this->getAdmin();
        $admin->handle();

        ob_start();
        $admin->html();
        return ob_get_clean();
    }

    /**
     * The local configuration of the wiki, read from the file that was written
     *
     * @return array
     */
    protected function getLocalConf()
    {
        $conf = [];
        include DOKU_CONF . 'local.php';
        return $conf;
    }

    /**
     * The page shows the certificate of the wiki but never its key
     */
    public function testNoPrivateKey()
    {
        $admin = $this->getAdmin();

        ob_start();
        $admin->html();
        $html = ob_get_clean();

        $this->assertStringContainsString('BEGIN CERTIFICATE', $html);
        $this->assertStringNotContainsString('PRIVATE KEY', $html);
    }

    /**
     * The page gives the address of the SP metadata
     */
    public function testMetadataLink()
    {
        $admin = $this->getAdmin();

        ob_start();
        $admin->html();
        $html = ob_get_clean();

        $this->assertStringContainsString(hsc(DOKU_URL . DOKU_SCRIPT . '?do=saml'), $html);
    }

    /**
     * The page reads all five settings out of the metadata
     */
    public function testParse()
    {
        $html = $this->showMetadata($this->getIdpMetadata());

        // the hidden field holds the same text escaped, so match the cell of the table
        $this->assertStringContainsString('>' . hsc(self::IDPENTITY) . '<', $html);
        $this->assertStringContainsString('>https://idp.example.org/sso-from-metadata<', $html);
        $this->assertStringContainsString('>https://idp.example.org/slo-from-metadata<', $html);
        $this->assertStringContainsString($this->getCertBody(), $html);
        $this->assertStringContainsString('<td>sign_requests</td>', $html);
    }

    /**
     * The wiki signs its requests when the identity provider asks for it
     *
     * An identity provider says so with WantAuthnRequestsSigned. The attribute is
     * optional and counts as false when it is missing.
     */
    public function testParseSignRequests()
    {
        $found = [
            'missing' => $this->showMetadata($this->getIdpMetadata()),
            'false' => $this->showMetadata($this->getIdpMetadata(['wantSignedRequests' => 'false'])),
            'true' => $this->showMetadata($this->getIdpMetadata(['wantSignedRequests' => 'true'])),
            'one' => $this->showMetadata($this->getIdpMetadata(['wantSignedRequests' => '1'])),
        ];

        $row = static fn($html) => preg_match(
            '/<td>sign_requests<\/td>.*?<\/td><td><pre class="code">(\d)</s',
            $html,
            $m
        ) ? $m[1] : 'no row';

        $this->assertEquals('0', $row($found['missing']));
        $this->assertEquals('0', $row($found['false']));
        $this->assertEquals('1', $row($found['true']));
        $this->assertEquals('1', $row($found['one']));
    }

    /**
     * An address without a scheme is refused before the wiki opens a connection
     */
    public function testUrlWithoutScheme()
    {
        global $INPUT;
        global $MSG;

        $INPUT->set('url', 'localhost:18080/realms/dokuwiki/protocol/saml/descriptor');
        $this->getAdmin()->handle();

        $this->assertCount(1, $MSG);
        $this->assertEquals('error', $MSG[0]['lvl']);
        $this->assertStringContainsString('localhost:18080', $MSG[0]['msg']);
    }

    /**
     * An address field that holds whitespace alone starts no download
     */
    public function testUrlOnlyWhitespace()
    {
        global $INPUT;
        global $MSG;
        $INPUT->set('url', "  \n\t ");

        $html = $this->showMetadata($this->getIdpMetadata());

        $this->assertEquals([], $MSG);
        $this->assertStringContainsString('>https://idp.example.org/sso-from-metadata<', $html);
    }

    /**
     * A pasted document is read with the whitespace that the copy brought along
     *
     * An XML declaration is valid at the start of the document only.
     */
    public function testXmlWithWhitespace()
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . $this->getIdpMetadata();

        $html = $this->showMetadata("\n  " . $xml . "  \n");

        $this->assertStringContainsString('>https://idp.example.org/sso-from-metadata<', $html);
    }

    /**
     * The page takes every signing certificate of the metadata
     */
    public function testParseTwoCertificates()
    {
        $html = $this->showMetadata($this->getIdpMetadata(['signers' => ['idp', 'other']]));

        $this->assertStringContainsString($this->getCertBody('idp'), $html);
        $this->assertStringContainsString($this->getCertBody('other'), $html);
    }

    /**
     * Every signing certificate of the metadata becomes a PEM block of the setting
     */
    public function testApplyTwoCertificates()
    {
        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['signers' => ['idp', 'other']]));
        $INPUT->set('apply', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', getSecurityToken());

        $this->getAdmin()->handle();

        $certificate = $this->getLocalConf()['plugin']['saml']['certificate'];
        $this->assertEquals(2, substr_count($certificate, '-----BEGIN CERTIFICATE-----'));
        $this->assertStringContainsString(trim(Utils::formatCert($this->getCertBody('idp'))), $certificate);
        $this->assertStringContainsString(trim(Utils::formatCert($this->getCertBody('other'))), $certificate);
    }

    /**
     * An identity provider that speaks the POST binding only is of no use
     */
    public function testParseWrongBinding()
    {
        $html = $this->showMetadata($this->getIdpMetadata(['ssoBinding' => Constants::BINDING_HTTP_POST]));

        $this->assertStringContainsString('No Data Found', $html);
    }

    /**
     * A Single Logout service of another binding is dropped, the rest stays
     */
    public function testParseWrongLogoutBinding()
    {
        $html = $this->showMetadata($this->getIdpMetadata(['sloBinding' => Constants::BINDING_HTTP_POST]));

        $this->assertStringContainsString('>https://idp.example.org/sso-from-metadata<', $html);
        $this->assertStringNotContainsString('>https://idp.example.org/slo-from-metadata<', $html);
    }

    /**
     * A setting without a value gives an empty cell, not an empty block
     */
    public function testEmptyValue()
    {
        $html = $this->showMetadata($this->getIdpMetadata(['sloBinding' => Constants::BINDING_HTTP_POST]));

        $this->assertStringContainsString('<td></td>', $html);
        $this->assertStringNotContainsString('<pre class="code"></pre>', $html);
    }

    /**
     * Something that is not metadata gives no settings
     */
    public function testParseBroken()
    {
        $html = $this->showMetadata('this is not a metadata document');

        $this->assertStringContainsString('No Data Found', $html);
    }

    /**
     * A confirmed request writes the values of the metadata into the configuration
     */
    public function testApply()
    {
        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['entityId' => 'https://new.example.org/']));
        $INPUT->set('apply', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', getSecurityToken());

        $this->getAdmin()->handle();

        $conf = $this->getLocalConf();
        $this->assertEquals('https://new.example.org/', $conf['plugin']['saml']['idPEntityID']);
        $this->assertEquals('https://idp.example.org/sso-from-metadata', $conf['plugin']['saml']['endpoint']);
        $this->assertEquals('https://idp.example.org/slo-from-metadata', $conf['plugin']['saml']['slo_endpoint']);
        $this->assertEquals(
            trim(Utils::formatCert($this->getCertBody())),
            $conf['plugin']['saml']['certificate']
        );
    }

    /**
     * Apply writes what the identity provider asks for about signed requests
     */
    public function testApplySignRequests()
    {
        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['wantSignedRequests' => 'true']));
        $INPUT->set('apply', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', getSecurityToken());

        $this->getAdmin()->handle();

        $this->assertEquals(1, $this->getLocalConf()['plugin']['saml']['sign_requests']);
    }

    /**
     * A request without a security token changes no setting
     */
    public function testApplyNeedsToken()
    {
        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['entityId' => 'https://new.example.org/']));
        $INPUT->set('apply', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', 'not the token');

        $this->getAdmin()->handle();

        $this->assertArrayNotHasKey('saml', $this->getLocalConf()['plugin'] ?? []);
    }

    /**
     * A request without the confirmation changes no setting
     */
    public function testApplyNeedsConfirmation()
    {
        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['entityId' => 'https://new.example.org/']));
        $INPUT->set('apply', 1);
        $INPUT->set('sectok', getSecurityToken());

        $this->getAdmin()->handle();

        $this->assertArrayNotHasKey('saml', $this->getLocalConf()['plugin'] ?? []);
    }

    /**
     * A configuration that the wiki cannot write stays as it is
     */
    public function testApplyNeedsWritePermission()
    {
        chmod(DOKU_CONF . 'local.php', 0444);
        if (is_writable(DOKU_CONF . 'local.php')) {
            $this->markTestSkipped('this user writes a file without the permission for it');
        }

        global $INPUT;
        $INPUT->set('xml', $this->getIdpMetadata(['entityId' => 'https://new.example.org/']));
        $INPUT->set('apply', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', getSecurityToken());

        $this->getAdmin()->handle();

        $this->assertArrayNotHasKey('saml', $this->getLocalConf()['plugin'] ?? []);
    }

    /**
     * A request without a security token does not change the key
     */
    public function testRotateNeedsToken()
    {
        global $INPUT;
        $keys = new KeyStore();
        $before = $keys->getCertificate();

        $INPUT->set('rotate', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', 'not the token');
        $this->getAdmin()->handle();

        $this->assertEquals($before, $keys->getCertificate());
    }

    /**
     * A request without the confirmation does not change the key
     */
    public function testRotateNeedsConfirmation()
    {
        global $INPUT;
        $keys = new KeyStore();
        $before = $keys->getCertificate();

        $INPUT->set('rotate', 1);
        $INPUT->set('sectok', getSecurityToken());
        $this->getAdmin()->handle();

        $this->assertEquals($before, $keys->getCertificate());
    }

    /**
     * A confirmed request creates a new key and certificate
     */
    public function testRotate()
    {
        global $INPUT;
        $keys = new KeyStore();
        $before = $keys->getCertificate();

        $INPUT->set('rotate', 1);
        $INPUT->set('confirm', 1);
        $INPUT->set('sectok', getSecurityToken());
        $this->getAdmin()->handle();

        $this->assertNotEquals($before, $keys->getCertificate());
        $this->assertTrue(openssl_x509_check_private_key($keys->getCertificate(), $keys->getKey()));
    }
}
