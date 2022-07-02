<?php

namespace Laragear\WebAuthn\Attestation\Stubs;

class CredentialPublicKey
{
    /**
     * Create a DTO for CredentialPublicKey
     * @param int $kty
     * @param string $x
     * @param string $y
     * @return void
     */
    public function __construct(
        public int $kty,
        public int $alg,
        // ECC
        public string|null $x,
        public string|null $y,
        // RSA
        public string $n,
        public string $e,
        public string $crv,
    ) {
        //
    }
}
