<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\SharedPipes\CheckRelyingPartyHashSame as BaseCheckRelyingPartyHashSame;

use function parse_url;

use const PHP_URL_HOST;

/**
 * 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CheckRelyingPartyHashSame extends BaseCheckRelyingPartyHashSame
{
    /**
     * Return the Attestation data to check the RP ID Hash.
     */
    protected function authenticatorData(AssertionValidation|AttestationValidation $validation): AuthenticatorData
    {
        return $validation->attestationObject->authenticatorData;
    }

    /**
     * Return the Relying Party ID from the config or credential.
     */
    protected function relyingPartyId(AssertionValidation|AttestationValidation $validation): string
    {
        return $this->config->get('webauthn.relying_party.id')
            ?? parse_url($this->config->get('app.url'), PHP_URL_HOST);
    }
}
