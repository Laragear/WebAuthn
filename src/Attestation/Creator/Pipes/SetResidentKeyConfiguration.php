<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Enums\ResidentKey;
use Laragear\WebAuthn\Enums\UserVerification;

/**
 * @internal
 */
class SetResidentKeyConfiguration
{
    /**
     * Handle the Attestation creation.
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $attestable->json->set('authenticatorSelection.residentKey', $attestable->residentKey->value);

        $verifiesUser = $attestable->residentKey === ResidentKey::Required;

        $attestable->json->set('authenticatorSelection.requireResidentKey', $verifiesUser);

        if ($verifiesUser) {
            $attestable->userVerification = UserVerification::Required;
        }

        return $next($attestable);
    }
}
