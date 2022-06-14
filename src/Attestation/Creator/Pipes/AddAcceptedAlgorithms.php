<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;

/**
 * @internal
 */
class AddAcceptedAlgorithms
{
    /**
     * Handle the Attestation creation
     *
     * @param  \Laragear\WebAuthn\Attestation\Creator\AttestationCreation  $attestable
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $attestable->json->set('pubKeyCredParams', [
            ['type' => 'public-key', 'alg' => -7],
            ['type' => 'public-key', 'alg' => -257],
        ]);

        // Currently we don't support direct attestation. In other words, it won't ask
        // for attestation data from the authenticator to cross-check later against
        // root certificates. We may add this in the future, but not guaranteed.
        $attestable->json->set('attestation', 'none');

        return $next($attestable);
    }
}
