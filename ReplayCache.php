<?php

namespace dokuwiki\plugin\saml;

/**
 * The assertions that were used already
 *
 * An assertion is valid for a short time only. An attacker who gets a copy of a response
 * may send it a second time inside that window. The cache keeps the identifier of every
 * used assertion until the assertion expires and refuses it in the meantime.
 */
class ReplayCache
{
    /**
     * How long an assertion without an expiry time is kept, in seconds
     *
     * The Web Browser SSO profile demands a NotOnOrAfter in the SubjectConfirmationData,
     * but the library accepts an assertion without one. This is the lifetime for that
     * case.
     */
    protected const DEFAULTLIFETIME = 600;

    /** @var string the directory that holds one file per used assertion */
    protected $dir;

    /**
     * @param string $dir the directory for the cache, a directory in the wiki cache by default
     */
    public function __construct($dir = '')
    {
        global $conf;
        $this->dir = $dir ?: $conf['cachedir'] . '/saml/replay';
    }

    /**
     * Was this assertion used before?
     *
     * An assertion that expired stays known until the cleanup removes it. The library
     * refuses an expired assertion anyway.
     *
     * @param string $id the identifier of the assertion
     * @return bool
     */
    public function isKnown($id)
    {
        return file_exists($this->getFile($id));
    }

    /**
     * Keep this assertion until it expires
     *
     * @param string $id the identifier of the assertion
     * @param int|null $expires when the assertion is no longer valid
     * @return void
     */
    public function add($id, $expires = null)
    {
        $this->cleanup();

        if (!$expires) $expires = time() + self::DEFAULTLIFETIME;

        $file = $this->getFile($id);
        io_makeFileDir($file);
        touch($file, $expires);
    }

    /**
     * Remove the assertions that expired
     *
     * @return void
     */
    public function cleanup()
    {
        $now = time();
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            if (filemtime($file) <= $now) @unlink($file);
        }
    }

    /**
     * The file that stands for one assertion
     *
     * @param string $id the identifier of the assertion
     * @return string
     */
    protected function getFile($id)
    {
        return $this->dir . '/' . md5($id);
    }
}
