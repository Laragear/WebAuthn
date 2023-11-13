<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use function hash_equals;
use function parse_url;
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
        if (!$host = parse_url($validation->clientDataJson->origin, PHP_URL_HOST)) {
            static::throw($validation, 'Relying Party ID is invalid.');
        }

        $current = parse_url(
            $this->config->get('webauthn.relying_party.http_scheme') . '' . $this->config->get('webauthn.relying_party.id') ?: $this->config->get('app.url'), PHP_URL_HOST
        );

        // Check the host is the same or is a subdomain of the current config domain.
        if (hash_equals($current, $host) || Str::is("*.$current", $host)) {
            return $next($validation);
        }

        static::throw($validation, 'Relying Party ID not scoped to current.');
    }
}
