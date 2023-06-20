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

        // This should make the browser accept any device. If we don't set it as `null`, some
        // Android devices will default to cross-platform (FIDO, USB) or platform (Android
        // Safenet, Windows Hello, Apple ID), instead of allowing for all device types.
        $attestable->json->set('authenticatorSelection.authenticatorAttachment', null);

        return $next($attestable);
    }
}
