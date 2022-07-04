<?php

namespace Laragear\WebAuthn\Attestation\Stubs;

/**
 * @codeCoverageIgnore
 */
class AttestedCredentialData
{
    /**
     * Create a DTO for Attested Credential Data
     *
     * @param string $aaguid
     * @param string $credentialId
     * @param CredentialPublicKey $credentialPublicKey
     * @param bool $userVerified
     * @param bool $userPresent
     * @return void
     */
    public function __construct(
        public string $aaguid,
        public string $credentialId,
        public CredentialPublicKey $credentialPublicKey,
        public bool $userVerified,
        public bool $userPresent
    ) {
        //
    }
}
