<?php

namespace Laragear\WebAuthn\Attestation\Stubs;

class AttestationFlags
{
    /**
     * Create a DTO for Attested Flags
     *
     * @param bool $userVerified
     * @param bool $userPresent
     * @param bool $attestedDataIncluded
     * @param bool $extensionDataIncluded
     * @return void
     */
    public function __construct(
        public bool $userVerified,
        public bool $userPresent,
        public bool $attestedDataIncluded,
        public bool $extensionDataIncluded,
    ) {
        //
    }
}
