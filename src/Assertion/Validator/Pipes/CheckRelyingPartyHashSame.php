<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\SharedPipes\CheckRelyingPartyHashSame as BaseCheckRelyingPartyHashSame;

/**
 * @internal
 */
class CheckRelyingPartyHashSame extends BaseCheckRelyingPartyHashSame
{
    /**
     * Return the Attestation data to check the RP ID Hash.
     */
    protected function authenticatorData(AssertionValidation|AttestationValidation $validation): AuthenticatorData
    {
        return $validation->authenticatorData;
    }

    /**
     * Return the Relying Party ID from the config or credential.
     */
    protected function relyingPartyId(AssertionValidation|AttestationValidation $validation): string
    {
        return $validation->credential->rp_id;
    }
}
