<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\KeyStore;
use DokuWikiTest;

/**
 * Tests for the key pair of this wiki
 *
 * @group plugin_saml
 * @group plugins
 */
class KeyStoreTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

    /** @var string the directory of the store under test */
    protected $dir;

    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();
        $this->dir = TMP_DIR . '/samlkeys';
        io_mkdir_p($this->dir);
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
    }

    /**
     * The store creates a key pair when it finds none
     */
    public function testGenerate()
    {
        $keys = new KeyStore($this->dir);
        $this->assertFalse($keys->exists());

        $key = $keys->getKey();

        $this->assertTrue($keys->exists());
        $this->assertStringContainsString('PRIVATE KEY', $key);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $keys->getCertificate());
        $this->assertFileExists($this->dir . '/_saml.key');
        $this->assertFileExists($this->dir . '/_saml.crt');
    }

    /**
     * The certificate names the host of the wiki and is valid for years
     */
    public function testCertificate()
    {
        $keys = new KeyStore($this->dir);
        $data = openssl_x509_parse($keys->getCertificate());

        $this->assertEquals(parse_url(DOKU_URL, PHP_URL_HOST), $data['subject']['CN']);
        $this->assertEquals($data['subject'], $data['issuer']); // self signed
        $this->assertGreaterThan(time() + 3600 * 24 * 365 * 9, $keys->getExpiry());
    }

    /**
     * A second call gives the same key, it is not created again
     */
    public function testKeepsKey()
    {
        $keys = new KeyStore($this->dir);
        $first = $keys->getCertificate();

        $other = new KeyStore($this->dir);

        $this->assertEquals($first, $other->getCertificate());
    }

    /**
     * A change creates a new key pair and keeps nothing of the one before
     */
    public function testRotate()
    {
        $keys = new KeyStore($this->dir);
        $before = $keys->getCertificate();

        $keys->rotate();

        $this->assertNotEquals($before, $keys->getCertificate());
        $this->assertTrue(openssl_x509_check_private_key($keys->getCertificate(), $keys->getKey()));
        $this->assertCount(2, glob($this->dir . '/*')); // the key and the certificate
    }

    /**
     * Only the owner may read the private key
     */
    public function testKeyIsProtected()
    {
        $keys = new KeyStore($this->dir);
        $keys->getKey();

        $this->assertEquals('0600', substr(sprintf('%o', fileperms($this->dir . '/_saml.key')), -4));
    }

}
