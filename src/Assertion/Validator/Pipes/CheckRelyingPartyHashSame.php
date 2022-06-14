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
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation|\Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @return \Laragear\WebAuthn\Attestation\AuthenticatorData
     */
    protected function authenticatorData(AssertionValidation|AttestationValidation $validation): AuthenticatorData
    {
        return $validation->authenticatorData;
    }

    /**
     * Return the Relying Party ID from the config or credential.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation|\Laragear\WebAuthn\Attestation\Validator\AttestationValidation  $validation
     * @return string
     */
    protected function relyingPartyId(AssertionValidation|AttestationValidation $validation): string
    {
        return $validation->credential->rp_id;
    }
}
