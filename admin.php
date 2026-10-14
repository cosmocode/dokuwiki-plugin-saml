<?php

use dokuwiki\Extension\AdminPlugin;
use dokuwiki\Form\Form;
use dokuwiki\HTTP\DokuHTTPClient;
use dokuwiki\plugin\config\core\Configuration;
use dokuwiki\plugin\saml\KeyStore;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\IdPMetadataParser;
use OneLogin\Saml2\Utils;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class admin_plugin_saml extends AdminPlugin
{
    /** @var string the metadata of the identity provider */
    protected $metadata = '';

    /** @var array the settings that the metadata gave, setting name to value */
    protected $found = [];

    /** @inheritdoc */
    public function handle()
    {
        global $INPUT;

        if ($INPUT->has('rotate')) {
            $this->handleRotate();
            return;
        }

        $this->metadata = $this->getIdpMetadata();
        if ($this->metadata === '') return;

        $this->found = $this->getSettings($this->metadata);
        if ($this->found === []) return;

        if ($INPUT->bool('apply')) $this->handleApply();
    }

    /** @inheritdoc */
    public function html()
    {
        echo '<div id="saml__admin">';
        echo $this->locale_xhtml('intro');

        $this->htmlMetadataForm();
        $this->htmlResult();
        $this->htmlKey();
        echo '</div>';
    }

    /**
     * The metadata of the identity provider that the admin gave
     *
     * Both values are trimmed: a copy and paste often brings whitespace along, which
     * makes an address unreadable for the HTTP client and an XML document unreadable
     * for the parser.
     *
     * @return string the XML, empty when the admin gave none or the download failed
     */
    protected function getIdpMetadata()
    {
        global $INPUT;

        $url = trim($INPUT->str('url'));
        if ($url === '') return trim($INPUT->str('xml'));

        $parts = parse_url($url);
        if (empty($parts['host']) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)) {
            msg(sprintf($this->getLang('err_url'), hsc($url)), -1);
            return '';
        }

        $http = new DokuHTTPClient();
        $xml = $http->get($url);
        if ($xml === false) {
            msg(sprintf($this->getLang('err_download'), hsc($http->error)), -1);
            return '';
        }

        return $xml;
    }

    /**
     * The settings of this plugin that the metadata of the identity provider holds
     *
     * @param string $xml the metadata
     * @return array setting name to value, empty when the metadata holds no usable data
     */
    protected function getSettings($xml)
    {
        try {
            $info = IdPMetadataParser::parseXML($xml);
            $signRequests = $this->getSignRequests($xml);
        } catch (Exception $e) {
            msg(sprintf($this->getLang('err_parse'), hsc($e->getMessage())), -1);
            return [];
        }

        $idp = $info['idp'] ?? [];
        $data = [
            'idPEntityID' => $idp['entityId'] ?? '',
            'endpoint' => $this->getRedirectUrl($idp['singleSignOnService'] ?? []),
            'slo_endpoint' => $this->getRedirectUrl($idp['singleLogoutService'] ?? []),
            'certificate' => $this->getCertificates($idp),
            'sign_requests' => $signRequests,
        ];

        // a login is not possible without these three
        if ($data['idPEntityID'] === '' || $data['endpoint'] === '' || $data['certificate'] === '') {
            return [];
        }

        return $data;
    }

    /**
     * The address of a service of the identity provider
     *
     * The plugin supports the HTTP-Redirect binding only.
     *
     * @param array $service the url and the binding, as the parser gives them
     * @return string the address, empty when there is none for this binding
     */
    protected function getRedirectUrl($service)
    {
        if ($service === []) return '';

        if ($service['binding'] !== Constants::BINDING_HTTP_REDIRECT) {
            msg(sprintf($this->getLang('err_binding'), hsc($service['url'])), -1);
            return '';
        }

        return $service['url'];
    }

    /**
     * Does the identity provider ask for a signature on the requests of this wiki?
     *
     * The parser of the library drops this attribute of the metadata. Without it the
     * attribute counts as false, which the schema prescribes.
     *
     * @param string $xml the metadata
     * @return int 1 when the identity provider asks for signed requests
     * @throws Exception when the metadata cannot be read
     */
    protected function getSignRequests($xml)
    {
        $dom = Utils::loadXML(new DOMDocument(), $xml);
        if (!$dom) return 0;

        // the parser takes the first descriptor as well
        $descriptors = Utils::query($dom, '//md:EntityDescriptor/md:IDPSSODescriptor');
        if ($descriptors->length === 0) return 0;

        $want = $descriptors->item(0)->getAttribute('WantAuthnRequestsSigned');
        return in_array($want, ['true', '1'], true) ? 1 : 0;
    }

    /**
     * All signing certificates of the identity provider
     *
     * @param array $idp the identity provider part of the parsed metadata
     * @return string the certificates in PEM format, one block after the other
     */
    protected function getCertificates($idp)
    {
        if (isset($idp['x509certMulti']['signing'])) {
            $certs = $idp['x509certMulti']['signing'];
        } elseif (isset($idp['x509cert'])) {
            // the parser drops x509certMulti when the metadata holds one certificate
            $certs = [$idp['x509cert']];
        } else {
            return '';
        }

        return trim(implode("\n", array_map(static fn($cert) => Utils::formatCert($cert), $certs)));
    }

    /**
     * Write the values of the metadata into the configuration of this wiki
     *
     * updateSettings() of the configuration manager gives a new value to every setting
     * that the caller does not name, so this changes the four settings one by one.
     *
     * @return void
     */
    protected function handleApply()
    {
        global $INPUT;
        global $ID;
        global $plugin_controller;

        if (!checkSecurityToken()) return;

        if (!$INPUT->bool('confirm')) {
            msg($this->getLang('apply_needconfirm'), -1);
            return;
        }

        if (!$plugin_controller->isEnabled('config')) {
            msg($this->getLang('apply_noconfig'), -1);
            return;
        }

        $configuration = new Configuration();
        if ($configuration->isLocked()) {
            msg($this->getLang('apply_locked'), -1);
            return;
        }

        $settings = $configuration->getSettings();
        $prefix = 'plugin' . Configuration::KEYMARKER . 'saml' . Configuration::KEYMARKER;
        $protected = [];

        foreach ($this->found as $key => $value) {
            $setting = $settings[$prefix . $key];
            if ($setting->isProtected()) {
                $protected[] = $key;
                continue;
            }
            $setting->update($value);
            if ($setting->hasError()) {
                msg($this->getLang('apply_error'), -1);
                return;
            }
        }
        if ($protected !== []) {
            msg(sprintf($this->getLang('apply_protected'), hsc(implode(', ', $protected))), -1);
        }

        try {
            // a newer conf/local.php resets the caches of the wiki
            $configuration->save();
        } catch (Exception) {
            msg($this->getLang('apply_error'), -1);
            return;
        }

        msg($this->getLang('apply_done'), 1);
        send_redirect(wl($ID, ['do' => 'admin', 'page' => 'saml'], true, '&'));
    }

    /**
     * Create a new key pair for this wiki
     *
     * @return void
     */
    protected function handleRotate()
    {
        global $INPUT;

        if (!checkSecurityToken()) return;

        if (!$INPUT->bool('confirm')) {
            msg($this->getLang('key_needconfirm'), -1);
            return;
        }

        try {
            (new KeyStore())->rotate();
            msg($this->getLang('key_new'), 1);
        } catch (Exception $e) {
            msg(hsc($e->getMessage()), -1);
        }
    }

    /**
     * The form that asks for the metadata of the identity provider
     *
     * @return void
     */
    protected function htmlMetadataForm()
    {
        $form = new Form();
        $form->addFieldsetOpen($this->getLang('meta_manage'));

        $url = $form->addTextInput('url', $this->getLang('meta_url'))
            ->attr('placeholder', 'https://idp.example.edu/idp/shibboleth');
        if ($this->metadata !== '') $url->val('')->useInput(false);

        $form->addTextarea('xml', $this->getLang('meta_xml'))
            ->val($this->metadata)
            ->useInput(false)
            ->attr('rows', 10)
            ->attr('placeholder', "<EntityDescriptor ...>\n  ...\n</EntityDescriptor>");

        $form->addButton('go', hsc($this->getLang('meta_submit')))->attr('type', 'submit');

        $form->addFieldsetClose();
        echo $form->toHTML();
    }

    /**
     * What the metadata of the identity provider gave
     *
     * @return void
     */
    protected function htmlResult()
    {
        if ($this->metadata === '') return;

        if ($this->found === []) {
            echo $this->locale_xhtml('notfound');
            return;
        }

        echo $this->locale_xhtml('found');
        $this->htmlComparison();
        $this->htmlApplyForm();
    }

    /**
     * The values of the metadata next to the values that the wiki uses now
     *
     * @return void
     */
    protected function htmlComparison()
    {
        echo '<table class="inline">';
        echo '<tr>';
        echo '<th>' . $this->getLang('cmp_setting') . '</th>';
        echo '<th>' . $this->getLang('cmp_current') . '</th>';
        echo '<th>' . $this->getLang('cmp_found') . '</th>';
        echo '</tr>';
        foreach ($this->found as $key => $value) {
            echo '<tr>';
            echo '<td>' . hsc($key) . '</td>';
            $this->htmlValue($this->getConf($key));
            $this->htmlValue($value);
            echo '</tr>';
        }
        echo '</table>';
    }

    /**
     * A cell of the comparison with one value in it
     *
     * The block keeps the line breaks of a certificate.
     *
     * @param string $value
     * @return void
     */
    protected function htmlValue($value)
    {
        if ((string)$value === '') {
            echo '<td></td>';
            return;
        }

        echo '<td><pre class="code">' . hsc($value) . '</pre></td>';
    }

    /**
     * The button that writes the values of the metadata into the configuration
     *
     * @return void
     */
    protected function htmlApplyForm()
    {
        $form = new Form();
        $form->setHiddenField('xml', $this->metadata);
        $form->addFieldsetOpen($this->getLang('apply_manage'));
        $form->addCheckbox('confirm', $this->getLang('apply_confirm'));
        $form->addHTML('<br>');
        $form->addButton('apply', hsc($this->getLang('apply')))->attr('type', 'submit');
        $form->addFieldsetClose();
        echo $form->toHTML();
    }

    /**
     * The certificate of this wiki
     *
     * The private key stays in the wiki and is never shown.
     *
     * @return void
     */
    protected function htmlKey()
    {
        $keys = new KeyStore();

        echo $this->locale_xhtml('key');

        echo '<dl>';
        echo '<dt>' . $this->getLang('key_metadata') . '</dt>';
        $url = DOKU_URL . DOKU_SCRIPT . '?do=saml';
        echo '<dd><a href="' . hsc($url) . '" target="_blank">' . hsc($url) . '</a></dd>';
        echo '<dt>' . $this->getLang('key_expiry') . '</dt>';
        echo '<dd>' . hsc(dformat($keys->getExpiry())) . '</dd>';
        echo '</dl>';

        echo '<pre class="code">' . hsc($keys->getCertificate()) . '</pre>';

        $this->htmlRotateForm();
    }

    /**
     * The button that creates a new key pair for this wiki
     *
     * The identity provider needs the certificate of the wiki only to check a signed
     * message and to encrypt an assertion, so the warning of the form names a broken
     * login for these two settings alone.
     *
     * @return void
     */
    protected function htmlRotateForm()
    {
        $inUse = $this->getConf('sign_requests') || $this->getConf('want_encrypted');

        $form = new Form();
        $form->addFieldsetOpen($this->getLang('key_manage'));
        $form->addCheckbox('confirm', $this->getLang($inUse ? 'key_confirm' : 'key_confirm_unused'));
        $form->addHTML('<br>');
        $form->addButton('rotate', hsc($this->getLang('key_rotate')))->attr('type', 'submit');
        $form->addFieldsetClose();
        echo $form->toHTML();
    }
}
