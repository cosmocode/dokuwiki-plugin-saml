<?php

namespace dokuwiki\plugin\saml\test;

use admin_plugin_saml;
use dokuwiki\plugin\saml\KeyStore;

/**
 * Tests for the admin page of the plugin
 *
 * @group plugin_saml
 * @group plugins
 */
class AdminTest extends AbstractMessageTest
{
    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();

        // the core checks the security token for a logged in user only
        global $INPUT;
        $INPUT->server->set('REMOTE_USER', 'tester');
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

        $this->assertStringContainsString(hsc(wl('', ['do' => 'saml'], true, '&')), $html);
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
     * A confirmed request creates a new key and keeps the certificate of before
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
