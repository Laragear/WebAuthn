<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Illuminate\Config\Repository;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;

/**
 * @internal
 */
class AddRelyingParty
{
    /**
     * Create a new pipe instance.
     *
     * @param  \Illuminate\Config\Repository  $config
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the Attestation creation
     *
     * @param  \Laragear\WebAuthn\Attestation\Creator\AttestationCreation  $attestable
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(AttestationCreation $attestable, Closure $next): mixed
    {
        $attestable->json->set('rp.name', $this->config->get('webauthn.relying_party.name'));

        if (($id = $this->config->get('webauthn.relying_party.id')) !== '') {
            $attestable->json->set('rp.id', $id);
        }

        return $next($attestable);
    }
}
