<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Ramsey\Uuid\Uuid;
use function hash_equals;

/**
 * 6. Identify the user being authenticated and verify that this user is the owner of the public
 *    key credential source credentialSource identified by credential.id:
 *
 *    - If the user was identified before the authentication ceremony was initiated, e.g., via a
 *      username or cookie, verify that the identified user is the owner of credentialSource. If
 *      response.userHandle is present, let userHandle be its value. Verify that userHandle also
 *      maps to the same user.
 *
 *    - If the user was not identified before the authentication ceremony was initiated, verify
 *      that response.userHandle is present, and that the user identified by this value is the
 *      owner of credentialSource.
 *
 * @internal
 */
class CheckCredentialIsForUser
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @param  \Closure  $next
     * @return mixed
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->user) {
            $this->validateUser($validation);

            if ($validation->request->json('response.userHandle')) {
                $this->validateId($validation);
            }
        } else {
            $this->validateId($validation);
        }

        return $next($validation);
    }

    /**
     * Validate the user owns the Credential if it already exists in the validation procedure.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @return void
     */
    protected function validateUser(AssertionValidation $validation): void
    {
        // @phpstan-ignore-next-line
        if ($validation->credential->authenticatable()->isNot($validation->user)) {
            throw AssertionException::make('User is not owner of the stored credential.');
        }
    }

    /**
     * Validate the user ID of the response.
     *
     * @param  \Laragear\WebAuthn\Assertion\Validator\AssertionValidation  $validation
     * @return void
     */
    protected function validateId(AssertionValidation $validation): void
    {
        $handle = $validation->request->json('response.userHandle');

        if (! $handle || ! hash_equals(Uuid::fromString($validation->credential->user_id)->getHex()->toString(), $handle)) {
            throw AssertionException::make('User ID is not owner of the stored credential.');
        }
    }
}
