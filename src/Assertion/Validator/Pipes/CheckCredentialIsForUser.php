<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Ramsey\Uuid\Exception\InvalidUuidStringException;
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
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->user) {
            $this->validateUser($validation);

            if ($validation->json->get('response.userHandle')) {
                $this->validateId($validation);
            }
        } else {
            $this->validateId($validation);
        }

        return $next($validation);
    }

    /**
     * Validate the user owns the Credential if it already exists in the validation procedure.
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
     */
    protected function validateId(AssertionValidation $validation): void
    {
        // This try-catch block tries to decode the UUID from the "userHandle" response
        // of the authenticator, which is pushed from the application to be saved. If
        // the userHandle cannot be decoded and normalized, then surely is invalid.
        try {
            $handle = Uuid::fromString($validation->json->get('response.userHandle'));
        } catch (InvalidUuidStringException) {
            try {
                // This is required for compatibility with credentials created by versions
                // of Webpass that used SimpleWebAuthn/browser < v10.0.0
                $handle = Uuid::fromString(ByteBuffer::decodeBase64Url($validation->json->get('response.userHandle')));
            } catch (InvalidUuidStringException) {
                throw AssertionException::make('The userHandle is not a valid hexadecimal UUID (32/36 characters).');
            }
        }

        if (! hash_equals(Uuid::fromString($validation->credential->user_id)->getHex()->toString(), $handle->getHex()->toString())) {
            throw AssertionException::make('User ID is not owner of the stored credential.');
        }
    }
}
