<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Safe\Exceptions\UrlException;

use function Safe\parse_url;

abstract class CheckOriginSecure
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
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->clientDataJson === null) {
            static::throw($validation, 'Response has an empty origin.');
        }

        if ($validation->clientDataJson->origin === '') {
            static::throw($validation, 'Response has an empty origin.');
        }

        try {
            /** @var array{host:mixed, scheme: mixed} */
            $origin = parse_url($validation->clientDataJson->origin);
        } catch (UrlException) {
            static::throw($validation, 'Response origin is invalid.');
        }

        if (!isset($origin['host'], $origin['scheme'])) {
            static::throw($validation, 'Response origin is invalid.');
        }

        if ($origin['host'] !== 'localhost' && $origin['scheme'] !== 'https') {
            static::throw($validation, 'Response not made to a secure server (localhost or HTTPS).');
        }

        return $next($validation);
    }
}
