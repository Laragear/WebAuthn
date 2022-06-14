<?php

namespace Laragear\WebAuthn\Attestation\Creator\Pipes;

use Closure;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Cache\Factory;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\SessionChallenge;

/**
 * @internal
 */
class CreateAttestationChallenge
{
    use SessionChallenge;

    /**
     * Create a new pipe instance.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  \Illuminate\Contracts\Cache\Factory  $cache
     */
    public function __construct(protected Repository $config, protected Factory $cache)
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
        $attestable->json->set('timeout', $this->config->get('webauthn.challenge.timeout') * 1000);

        $challenge = $this->storeChallenge($attestable->request, $attestable->userVerification, [
            'user_uuid' => $attestable->json->get('user.id'),
            'user_handle' => $attestable->json->get('user.name'),
        ]);

        $attestable->json->set('challenge', $challenge->data);

        return $next($attestable);
    }
}
