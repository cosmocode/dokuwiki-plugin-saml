<?php

namespace dokuwiki\plugin\saml\test;

/**
 * Tests that the library refuses the responses that the plugin must not accept
 *
 * @group plugin_saml
 * @group plugins
 */
class ResponseTest extends AbstractMessageTest
{
    /**
     * A correct response is accepted
     */
    public function testValidResponse()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse();

        $saml->processResponse();

        $this->assertEquals([], $saml->getErrors(), $saml->getLastErrorReason() ?? '');
        $this->assertTrue($saml->isAuthenticated());
        $this->assertEquals(['andi'], $saml->getAttribute('login'));
    }

    /**
     * The session expiry of the assertion is available for the plugin
     */
    public function testSessionExpiration()
    {
        $expiry = time() + 1800;
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['sessionExpiry' => $expiry]);

        $saml->processResponse();

        $this->assertTrue($saml->isAuthenticated());
        $this->assertEquals($expiry, $saml->getSessionExpiration());
        $this->assertNotEmpty($saml->getLastAssertionId());
    }

    /**
     * An assertion may come without an expiry time of its own
     *
     * The Web Browser SSO profile demands a NotOnOrAfter in the SubjectConfirmationData,
     * but the library accepts an assertion without one. The replay cache then has to use
     * a lifetime of its own.
     */
    public function testNoAssertionExpiry()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['confirmationExpiry' => null]);

        $saml->processResponse();

        $this->assertTrue($saml->isAuthenticated(), $saml->getLastErrorReason() ?? '');
        $this->assertNull($saml->getLastAssertionNotOnOrAfter());
    }

    /**
     * A response without a signature is refused
     */
    public function testNoSignature()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['sign' => false]);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('No Signature found', $saml->getLastErrorReason());
    }

    /**
     * A response that another key signed is refused
     */
    public function testWrongCertificate()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['signer' => 'other']);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Signature validation failed', $saml->getLastErrorReason());
    }

    /**
     * A response with a broken signature is refused
     */
    public function testBrokenSignature()
    {
        $xml = base64_decode($this->getResponse());
        $xml = str_replace('<saml:AttributeValue>andi<', '<saml:AttributeValue>eve<', $xml);

        $saml = $this->getLib();
        $_POST['SAMLResponse'] = base64_encode($xml);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Reference validation failed', $saml->getLastErrorReason());
    }

    /**
     * A response for another service provider is refused
     */
    public function testWrongAudience()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['audience' => 'https://other.example.org/']);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Invalid audience for this Response', $saml->getLastErrorReason());
    }

    /**
     * A response for another address is refused
     */
    public function testWrongDestination()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['destination' => 'https://other.example.org/doku.php']);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('was received at', $saml->getLastErrorReason());
    }

    /**
     * A response of another identity provider is refused
     */
    public function testWrongIssuer()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['issuer' => 'https://other.example.org/']);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Invalid issuer in the Assertion/Response', $saml->getLastErrorReason());
    }

    /**
     * An assertion that is no longer valid is refused
     */
    public function testExpiredAssertion()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse([
            'notBefore' => time() - 600,
            'notOnOrAfter' => time() - 300,
        ]);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Could not validate timestamp', $saml->getLastErrorReason());
    }

    /**
     * An assertion that is not valid yet is refused
     */
    public function testFutureAssertion()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse([
            'notBefore' => time() + 300,
            'notOnOrAfter' => time() + 600,
        ]);

        $saml->processResponse();

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('Could not validate timestamp', $saml->getLastErrorReason());
    }

    /**
     * A response that answers the request of this wiki is accepted
     */
    public function testMatchingInResponseTo()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['inResponseTo' => '_request1']);

        $saml->processResponse('_request1');

        $this->assertTrue($saml->isAuthenticated(), $saml->getLastErrorReason() ?? '');
    }

    /**
     * A response that answers another request is refused
     */
    public function testWrongInResponseTo()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['inResponseTo' => '_request2']);

        $saml->processResponse('_request1');

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('does not match the ID of the AuthNRequest', $saml->getLastErrorReason());
    }

    /**
     * A response that answers no request at all is refused when this wiki sent one
     */
    public function testMissingInResponseTo()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse();

        $saml->processResponse('_request1');

        $this->assertFalse($saml->isAuthenticated());
        $this->assertStringContainsString('No InResponseTo at the Response', $saml->getLastErrorReason());
    }

    /**
     * A response that answers a request this wiki cannot see is accepted by the library
     *
     * The browser does not send the session cookie of the wiki with the cross site POST
     * of an identity provider on another domain, so the request id is missing although
     * this wiki did send a request. The plugin applies the allow_unsolicited setting to
     * this case, the library must not refuse it by itself.
     */
    public function testUnknownInResponseTo()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse(['inResponseTo' => '_request1']);

        $saml->processResponse();

        $this->assertTrue($saml->isAuthenticated(), $saml->getLastErrorReason() ?? '');
    }

    /**
     * A login that starts at the identity provider has no InResponseTo and is accepted
     */
    public function testUnsolicitedResponse()
    {
        $saml = $this->getLib();
        $_POST['SAMLResponse'] = $this->getResponse();

        $saml->processResponse();

        $this->assertTrue($saml->isAuthenticated(), $saml->getLastErrorReason() ?? '');
    }
}
