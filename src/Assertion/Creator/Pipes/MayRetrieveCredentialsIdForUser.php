<?php

namespace Laragear\WebAuthn\Assertion\Creator\Pipes;

use Closure;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Collection;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Models\WebAuthnCredential;

use function array_filter;

class MayRetrieveCredentialsIdForUser
{
    /**
     * Handle the incoming Assertion.
     */
    public function handle(AssertionCreation $assertion, Closure $next): mixed
    {
        // If there is a user found, we will pluck the IDs and add them as a binary buffer.
        if ($assertion->user) {
            $assertion->acceptedCredentials = $assertion->user->webAuthnCredentials()->get(['id', 'transports']);

            if ($assertion->acceptedCredentials->isNotEmpty()) {
                $assertion->json->set('allowCredentials', $this->parseCredentials($assertion->acceptedCredentials));
            }
        }

        return $next($assertion);
    }

    /**
     * Adapt all credentials into an `allowCredentials` digestible array.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Laragear\WebAuthn\Models\WebAuthnCredential>  $credentials
     * @return \Illuminate\Support\Collection<int, array{id?: mixed, type: string, transports?: non-empty-array<int, string>}>
     */
    protected function parseCredentials(EloquentCollection $credentials): Collection
    {
        return $credentials->map(static function (WebAuthnCredential $credential): array {
            return array_filter([
                'id' => $credential->getKey(),
                'type' => 'public-key',
                'transports' => $credential->transports,
            ]);
        });
    }
}
