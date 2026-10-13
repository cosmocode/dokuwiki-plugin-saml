<?php

namespace dokuwiki\plugin\saml\test;

use dokuwiki\plugin\saml\ReplayCache;
use DokuWikiTest;

/**
 * Tests for the assertions that were used already
 *
 * @group plugin_saml
 * @group plugins
 */
class ReplayCacheTest extends DokuWikiTest
{
    /** @inheritdoc */
    protected $pluginsEnabled = ['saml'];

    /** @var string the directory of the cache under test */
    protected $dir;

    /** @inheritdoc */
    public function setUp(): void
    {
        parent::setUp();
        $this->dir = TMP_DIR . '/samlreplay';
    }

    /** @inheritdoc */
    public function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        parent::tearDown();
    }

    /**
     * An assertion that was never seen is not known
     */
    public function testUnknown()
    {
        $cache = new ReplayCache($this->dir);

        $this->assertFalse($cache->isKnown('_assertion1'));
    }

    /**
     * An assertion that was used is known
     */
    public function testKnown()
    {
        $cache = new ReplayCache($this->dir);
        $cache->add('_assertion1', time() + 300);

        $this->assertTrue($cache->isKnown('_assertion1'));
        $this->assertFalse($cache->isKnown('_assertion2'));
    }

    /**
     * An assertion without an expiry time is kept for a while
     */
    public function testDefaultLifetime()
    {
        $cache = new ReplayCache($this->dir);
        $cache->add('_assertion1');

        $this->assertTrue($cache->isKnown('_assertion1'));
    }

    /**
     * An assertion that expired stays known until the cleanup removes it
     */
    public function testKnownAfterExpiry()
    {
        $cache = new ReplayCache($this->dir);
        io_mkdir_p($this->dir);
        touch($this->dir . '/' . md5('_assertion1'), time() - 1);

        $this->assertTrue($cache->isKnown('_assertion1'));
    }

    /**
     * The cache removes the assertions that expired
     */
    public function testCleanup()
    {
        $cache = new ReplayCache($this->dir);
        $cache->add('_new', time() + 300);
        touch($this->dir . '/' . md5('_old'), time() - 300);
        $this->assertCount(2, glob($this->dir . '/*'));

        $cache->cleanup();

        $this->assertCount(1, glob($this->dir . '/*'));
        $this->assertTrue($cache->isKnown('_new'));
        $this->assertFalse($cache->isKnown('_old'));
    }

    /**
     * An assertion that is added stays, the cleanup of the next add removes it
     */
    public function testAddExpired()
    {
        $cache = new ReplayCache($this->dir);
        $cache->add('_assertion1', time() - 1);
        $this->assertTrue($cache->isKnown('_assertion1'));

        $cache->add('_assertion2', time() + 300);

        $this->assertFalse($cache->isKnown('_assertion1'));
        $this->assertTrue($cache->isKnown('_assertion2'));
    }

    /**
     * The cache uses the cache directory of the wiki by default
     */
    public function testDefaultDirectory()
    {
        global $conf;
        $cache = new ReplayCache();
        $cache->add('_assertion1', time() + 300);

        $this->assertFileExists($conf['cachedir'] . '/saml/replay/' . md5('_assertion1'));
        $this->assertTrue($cache->isKnown('_assertion1'));
    }
}
