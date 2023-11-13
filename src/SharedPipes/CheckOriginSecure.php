<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use function parse_url;

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
        if (!$validation->clientDataJson->origin) {
            static::throw($validation, 'Response has an empty origin.');
        }

        $origin = parse_url($validation->clientDataJson->origin);

        if (!$origin) {
            static::throw($validation, 'Response origin is invalid.');
        }

        if($origin['scheme'] === 'android') {
            $fingerprint = config('webauthn.paths.android');
            $fingerprint = str_replace(':', '', $fingerprint);
            $binaryData = hex2bin($fingerprint);
            $base64Url = base64_encode($binaryData);
            $base64Url = str_replace(['+', '/', '='], ['-', '_', ''], $base64Url);
            $path = "apk-key-hash:" . $base64Url;

            if($path !== $origin['path']) {
                static::throw($validation, 'Response path doesn\'t match.');
            }

            return $next($validation);
        }

        if (!$origin || !isset($origin['host'], $origin['scheme'])) {
            static::throw($validation, 'Response origin is invalid.');
        }

        if ($origin['host'] !== 'localhost' && $origin['scheme'] !== 'https') {
            static::throw($validation, 'Response not made to a secure server (localhost or HTTPS).');
        }

        return $next($validation);
    }
}
