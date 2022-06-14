<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\WebAuthn;

/**
 * @internal
 */
class SetResidentKeyConfiguration
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
        if ($attestable->residentKey) {
            $attestable->json->set('authenticatorSelection.residentKey', $attestable->residentKey);

            $verifiesUser = $attestable->residentKey === WebAuthn::RESIDENT_KEY_REQUIRED;

            $attestable->json->set('authenticatorSelection.requireResidentKey', $verifiesUser);

            if ($verifiesUser) {
                $attestable->userVerification = WebAuthn::USER_VERIFICATION_REQUIRED;
            }
        }


        return $next($attestable);
    }
}
