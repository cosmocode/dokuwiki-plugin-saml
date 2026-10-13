<?php

namespace dokuwiki\plugin\saml;

use RuntimeException;

/**
 * The key pair of this wiki as a SAML service provider
 *
 * The wiki signs its messages with this key and receives encrypted assertions for it.
 * A self signed certificate is the standard for a service provider: the identity provider
 * compares the certificate with the copy that it has and does not check a chain. Only the
 * wiki creates the key pair and the private key never leaves the wiki.
 *
 * A new key pair replaces the one before it at once. The wiki keeps one private key only,
 * so it publishes one certificate only: a certificate whose key the wiki threw away would
 * invite the identity provider to encrypt an assertion that nobody can read.
 */
class KeyStore
{
    /** @var int the size of the RSA key */
    protected const KEYBITS = 3072;

    /** @var int how long a new certificate is valid, in days */
    protected const LIFETIME = 3650;

    /** @var string the directory that holds the key and the certificates */
    protected $dir;

    /**
     * @param string $dir the directory for the files, the meta directory of the wiki by default
     */
    public function __construct($dir = '')
    {
        global $conf;
        $this->dir = $dir ?: $conf['metadir'];
    }

    /**
     * The private key of this wiki
     *
     * @return string the key in PEM format
     * @throws RuntimeException when no key pair exists and none can be created
     */
    public function getKey()
    {
        if (!$this->exists()) $this->generate();
        return (string)io_readFile($this->getFile('.key'), false);
    }

    /**
     * The certificate of this wiki
     *
     * @return string the certificate in PEM format
     * @throws RuntimeException when no key pair exists and none can be created
     */
    public function getCertificate()
    {
        if (!$this->exists()) $this->generate();
        return (string)io_readFile($this->getFile('.crt'), false);
    }

    /**
     * The time at which the certificate of this wiki expires
     *
     * @return int a timestamp, 0 when the certificate cannot be read
     */
    public function getExpiry()
    {
        $data = openssl_x509_parse($this->getCertificate());
        if ($data === false) return 0;
        return (int)$data['validTo_time_t'];
    }

    /**
     * Create a new key pair
     *
     * The wiki signs with the new key at once. An identity provider that reads the SP
     * metadata follows by itself, one with a copy of the certificate needs the new
     * certificate from the admin.
     *
     * @return void
     * @throws RuntimeException when the key pair cannot be created
     */
    public function rotate()
    {
        $this->generate();
    }

    /**
     * Does a key pair exist?
     *
     * @return bool
     */
    public function exists()
    {
        return file_exists($this->getFile('.key')) && file_exists($this->getFile('.crt'));
    }

    /**
     * Create a new key pair and a self signed certificate for it
     *
     * @return void
     * @throws RuntimeException when the key pair cannot be created
     */
    protected function generate()
    {
        $key = openssl_pkey_new([
            'private_key_bits' => self::KEYBITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg' => 'sha256',
        ]);
        if ($key === false) {
            throw new RuntimeException('Could not create a key: ' . openssl_error_string());
        }

        $name = ['commonName' => parse_url(DOKU_URL, PHP_URL_HOST) ?: 'dokuwiki'];
        $csr = openssl_csr_new($name, $key, ['digest_alg' => 'sha256']);
        if ($csr === false) {
            throw new RuntimeException('Could not create a certificate request: ' . openssl_error_string());
        }

        $serial = random_int(1, PHP_INT_MAX);
        $crt = openssl_csr_sign($csr, null, $key, self::LIFETIME, ['digest_alg' => 'sha256'], $serial);
        if ($crt === false) {
            throw new RuntimeException('Could not sign the certificate: ' . openssl_error_string());
        }

        openssl_pkey_export($key, $keyPem);
        openssl_x509_export($crt, $crtPem);

        io_saveFile($this->getFile('.key'), $keyPem);
        chmod($this->getFile('.key'), 0600);
        io_saveFile($this->getFile('.crt'), $crtPem);
    }

    /**
     * One of the files of this store
     *
     * The underscore follows the convention of the core for a generated secret like
     * _htcookiesalt. cleanID() removes a leading underscore, so these files cannot
     * collide with the metadata of a page.
     *
     * @param string $suffix .key or .crt
     * @return string
     */
    protected function getFile($suffix)
    {
        return $this->dir . '/_saml' . $suffix;
    }
}
