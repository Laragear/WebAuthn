<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;

/**
 * @internal
 */
class MayRequireUserVerification
{
    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $attestable->json->set('authenticatorSelection.userVerification', $attestable->userVerification->value);

        return $next($attestable);
    }
}
