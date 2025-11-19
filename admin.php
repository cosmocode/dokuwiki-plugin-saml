<?php

/**
 * SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 * @author     Sam Yelman <sam.yelman@temple.edu>
 */

use dokuwiki\HTTP\DokuHTTPClient;

class admin_plugin_saml extends DokuWiki_Admin_Plugin
{
    protected $xml = '';

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
            header("X-XSS-Protection: 0");
            $this->xml = $INPUT->str('xml');
        }

    }

    public function html()
    {
        echo $this->locale_xhtml('intro');

        $form = new \dokuwiki\Form\Form();
        $form->addFieldsetOpen('Federation Metadata');


        $form->addTag('div')->attr('style', 'margin-bottom: 1em;');

        $form->addLabel('URL Option: Metadata Endpoint', "__url_input")
             ->attr('style', 'font-weight: 800; display: block; margin-bottom: 0.5em;');
        $url_input = $form->addTextInput('url')
                ->id("__url_input")
                ->attr("size", 60)
                ->attr("placeholder", "https://idp.example.edu/idp/shibboleth");
        if ($this->xml) $url_input->val('')->useInput(false);

        $form->addTag('/div');


        $form->addTag('div')->attr('style', 'margin-top: 2em;');
        $form->addLabel('Copy/Paste Option: The XML Metadata', "__xml_input")
             ->attr('style', 'font-weight: 800; display: block; margin-bottom: 1.5em;');

        $metadata_placeholder = <<<METADATAPLACEHOLDER
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

        $xml_input = $form->addTextarea('xml')
             ->id("__xml_input")
             ->val($this->xml)
             ->useInput(false)
             ->attr('rows', 10)
             ->attr('cols', 60)
             ->attr('placeholder', $metadata_placeholder);

        $form->addTag('/div');

        $form->addTag('div')->attr('style', 'margin-top: 1em;');
        $form->addButton('go', 'Submit')->attr('type', 'submit');
        $form->addTag('/div');

        $form->addFieldsetClose();
        echo $form->toHTML();

        if ($this->xml) {
            $data = $this->metaData($this->xml);
            if (count($data)) {
                echo $this->locale_xhtml('found');

                echo '<dl>';
                foreach ($data as $key => $val) {
                    echo '<dt>' . hsc($key) . '</dt>';
                    echo '<dd><code>' . hsc($val) . '</code></dd>';
                }
                echo '</dl>';
            } else {
                echo $this->locale_xhtml('notfound');
            }
        }
    }

    /**
     * Parse the metadata and return the configuration values
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

        $proto = '/md:EntityDescriptor/md:IDPSSODescriptor[@protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"]';
        $data['idPEntityID'] = (string)$xml['entityID'];
        $data['endpoint'] = (string)($xml->xpath($proto . '/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]'))[0]['Location'];
        $data['certificate'] = (string)($xml->xpath($proto . '/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'))[0];

        return $data;
    }


}
