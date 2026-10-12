<?php

use dokuwiki\Extension\AdminPlugin;
use dokuwiki\Form\Form;
use dokuwiki\HTTP\DokuHTTPClient;

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

        if (!$this->xml) return;

        $data = $this->metaData($this->xml);
        if ($data === []) {
            echo $this->locale_xhtml('notfound');
            return;
        }

        echo $this->locale_xhtml('found');
        echo '<dl>';
        foreach ($data as $key => $val) {
            echo '<dt>' . hsc($key) . '</dt>';
            echo '<dd><code>' . hsc($val) . '</code></dd>';
        }
        echo '</dl>';
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
