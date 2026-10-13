<?php

use dokuwiki\Extension\AdminPlugin;
use dokuwiki\Form\Form;
use dokuwiki\HTTP\DokuHTTPClient;
use dokuwiki\plugin\saml\KeyStore;

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */
class admin_plugin_saml extends AdminPlugin
{
    /** @var string the metadata of the identity provider */
    protected $xml = '';

    /** @inheritdoc */
    public function handle()
    {
        global $INPUT;

        if ($INPUT->has('rotate')) {
            $this->handleKey();
            return;
        }

        if ($INPUT->str('url')) {
            $http = new DokuHTTPClient();
            $xml = $http->get($INPUT->str('url'));
            if ($xml === false) {
                msg('Failed to download metadata. ' . hsc($http->error), -1);
            } else {
                $this->xml = $xml;
            }
        } elseif ($INPUT->has('xml')) {
            $this->xml = $INPUT->str('xml');
        }
    }

    /** @inheritdoc */
    public function html()
    {
        echo $this->locale_xhtml('intro');
        echo $this->getForm()->toHTML();

        if ($this->xml) {
            $data = $this->metaData($this->xml);
            if ($data === []) {
                echo $this->locale_xhtml('notfound');
            } else {
                echo $this->locale_xhtml('found');
                echo '<dl>';
                foreach ($data as $key => $val) {
                    echo '<dt>' . hsc($key) . '</dt>';
                    echo '<dd><code>' . hsc($val) . '</code></dd>';
                }
                echo '</dl>';
            }
        }

        $this->htmlKey();
    }

    /**
     * Create a new key pair for this wiki
     *
     * @return void
     */
    protected function handleKey()
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
     * The certificate of this wiki and the buttons that manage it
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
        $url = wl('', ['do' => 'saml'], true, '&');
        echo '<dd><a href="' . hsc($url) . '">' . hsc($url) . '</a></dd>';
        echo '<dt>' . $this->getLang('key_expiry') . '</dt>';
        echo '<dd>' . hsc(dformat($keys->getExpiry())) . '</dd>';
        echo '</dl>';

        echo '<pre class="code">' . hsc($keys->getCertificate()) . '</pre>';

        $form = new Form();
        $form->addFieldsetOpen($this->getLang('key_manage'));
        $form->addCheckbox('confirm', $this->getLang('key_confirm'));
        $form->addHTML('<br>');
        $form->addButton('rotate', hsc($this->getLang('key_rotate')))->attr('type', 'submit');
        $form->addFieldsetClose();
        echo $form->toHTML();
    }

    /**
     * The form that asks for the metadata of the identity provider
     *
     * @return Form
     */
    protected function getForm()
    {
        $placeholder = <<<METADATAPLACEHOLDER
<EntityDescriptor entityID="https://example-idp.org/idp/shibboleth"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
MIIC+jCCAeKgAwIBAgIUA1EXAMPLEONLY1234567890ABCDEFG...
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://login.example.org/idp/profile/SAML2/Redirect/SSO"/>
    </IDPSSODescriptor>
</EntityDescriptor>
METADATAPLACEHOLDER;

        $form = new Form();
        $form->addFieldsetOpen('Federation Metadata');

        $form->addTagOpen('div')->attr('style', 'margin-bottom: 1em;');
        $form->addLabel('URL Option: Metadata Endpoint', '__url_input')
            ->attr('style', 'font-weight: 800; display: block; margin-bottom: 0.5em;');
        $urlInput = $form->addTextInput('url')
            ->id('__url_input')
            ->attr('size', 60)
            ->attr('placeholder', 'https://idp.example.edu/idp/shibboleth');
        if ($this->xml) $urlInput->val('')->useInput(false);
        $form->addTagClose('div');

        $form->addTagOpen('div')->attr('style', 'margin-top: 2em;');
        $form->addLabel('Copy/Paste Option: The XML Metadata', '__xml_input')
            ->attr('style', 'font-weight: 800; display: block; margin-bottom: 1.5em;');
        $form->addTextarea('xml')
            ->id('__xml_input')
            ->val($this->xml)
            ->useInput(false)
            ->attr('rows', 10)
            ->attr('cols', 60)
            ->attr('placeholder', $placeholder);
        $form->addTagClose('div');

        $form->addTagOpen('div')->attr('style', 'margin-top: 1em;');
        $form->addButton('go', 'Submit')->attr('type', 'submit');
        $form->addTagClose('div');

        $form->addFieldsetClose();
        return $form;
    }

    /**
     * Parse the metadata and return the configuration values
     *
     * @param string $xml the metadata of the identity provider
     * @return array setting name to value, empty when the metadata could not be read
     */
    public function metaData($xml)
    {
        $xml = @simplexml_load_string($xml);
        if ($xml === false) {
            msg('Failed to parse the the XML', -1);
            return [];
        }

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $proto = '/md:EntityDescriptor/md:IDPSSODescriptor' .
            '[@protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"]';

        $sso = $xml->xpath($proto . '/md:SingleSignOnService' .
            '[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]');
        $cert = $xml->xpath($proto . '/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate');
        if (!$sso || !$cert) return [];

        return [
            'idPEntityID' => (string)$xml['entityID'],
            'endpoint' => (string)$sso[0]['Location'],
            'certificate' => (string)$cert[0],
        ];
    }
}
