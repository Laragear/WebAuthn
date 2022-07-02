<?php

namespace Laragear\WebAuthn\Attestation\Stubs;

class AttestedCredentialData
{
    /**
     * Create a DTO for Attested Credential Data
     *
     * @param int|bool $aaguid
     * @param string $credentialId
     * @param CredentialPublicKey $credentialPublicKey
     * @param bool $userVerified
     * @param bool $userPresent
     * @return void
     */
    public function __construct(
        public int|bool $aaguid,
        public string $credentialId,
        public CredentialPublicKey $credentialPublicKey,
        public bool $userVerified,
        public bool $userPresent
    ) {
        //
    }
}
