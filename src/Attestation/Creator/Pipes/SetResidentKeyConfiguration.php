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
        if ($attestable->residentKey) {
            $attestable->json->set('authenticatorSelection.residentKey', $attestable->residentKey->value);

            $verifiesUser = $attestable->residentKey === ResidentKey::REQUIRED;

            $attestable->json->set('authenticatorSelection.requireResidentKey', $verifiesUser);

            if ($verifiesUser) {
                $attestable->userVerification = UserVerification::REQUIRED;
            }
        }

        return $next($attestable);
    }
}
