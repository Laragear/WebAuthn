<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Safe\Exceptions\UrlException;

use function hash_equals;
use function Safe\parse_url;
use const PHP_URL_HOST;

/**
 * @internal
 */
abstract class CheckRelyingPartyIdContained
{
    use ThrowsCeremonyException;

    /**
     * Create a new pipe instance.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming WebAuthn Ceremony Validation.
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation|\Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  \Closure  $next
     * @return mixed
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        try {
            $host = parse_url($validation->clientDataJson->origin, PHP_URL_HOST);
        } catch (UrlException) {
            static::throw($validation, 'Relaying Party ID is invalid.');
        }

        try {
            $current = parse_url(
                $this->config->get('webauthn.relaying_party.id') ?? $this->config->get('app.url'),
                PHP_URL_HOST
            );
        } catch (UrlException) {
            static::throw($validation, 'Relaying Party ID is invalid.');
        }

        if (!is_string($host) || !is_string($current)) {
            static::throw($validation, 'Relying Party ID is not a string.');
        }


        // Check the host is the same or is a subdomain of the current config domain.
        if (hash_equals($current, $host) || Str::is("*.$current", $host)) {
            return $next($validation);
        }

        static::throw($validation, 'Relaying Party ID not scoped to current.');
    }
}
