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
     * Handle the Attestation creation
     *
     * @param  \Laragear\WebAuthn\Attestation\Creator\AttestationCreation  $attestable
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        if ($attestable->userVerification) {
            $attestable->json->set('authenticatorSelection.userVerification', $attestable->userVerification);
        }

        return $next($attestable);
    }
}
