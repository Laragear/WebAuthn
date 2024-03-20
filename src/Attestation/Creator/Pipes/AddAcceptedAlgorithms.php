<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;

use function function_exists;

/**
 * @internal
 */
class AddAcceptedAlgorithms
{
    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        // Here we set the supported algorithms to sign and check challenges. The
        // authenticator will pick one of these, create the public key, and tell
        // which type the key is. This way we can later validate the challenge.
        $algorithms = [
            AuthenticatorData::EC2_ES256,
            AuthenticatorData::RSA_RS256,
        ];

        if ($this->isSupportingEd25519()) {
            $algorithms[] = AuthenticatorData::OKP_EDDSA;
        }

        $attestable->json->set('pubKeyCredParams', $this->fillAlgorithms($algorithms));

        // Currently we don't support direct attestation. In other words, it won't ask
        // for attestation data from the authenticator to cross-check later against
        // root certificates. We may add this in the future, but not guaranteed.
        $attestable->json->set('attestation', 'none');

        return $next($attestable);
    }

    /**
     * Check if the server supports Ed25519 curves for public keys.
     *
     * @return bool
     */
    protected function isSupportingEd25519(): bool
    {
        // Check if the sodium function is available.
        return function_exists('sodium_crypto_sign_verify_detached');
    }

    /**
     * Transform the supported algorithms to an array the authenticator can understand.
     *
     * @param  int[]  ...$algorithms
     * @return array<array{type: 'public-key', alg: int}|int>
     */
    protected function fillAlgorithms(array $algorithms): array
    {
        foreach ($algorithms as $key => $algorithm) {
            $algorithms[$key] = ['type' => 'public-key', 'alg' => $algorithm];
        }

        return $algorithms;
    }
}
