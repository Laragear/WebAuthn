<?php

namespace Laragear\WebAuthn\Attestation;

use Laragear\WebAuthn\Attestation\Formats\Format;

/**
 * @internal
 */
class AttestationObject
{
    /**
     * Create a new Attestation Object.
     *
     * @param  \Laragear\WebAuthn\Attestation\AuthenticatorData  $authenticatorData
     * @param  \Laragear\WebAuthn\Attestation\Formats\Format  $format
     * @param  string  $formatName
     */
    public function __construct(
        public AuthenticatorData $authenticatorData,
        public Format $format,
        public string $formatName)
    {
        //
    }
}
