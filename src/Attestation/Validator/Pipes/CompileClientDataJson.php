<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Laragear\WebAuthn\SharedPipes\CompileClientDataJson as BaseCompileClientDataJson;

/**
 * 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
 *
 * 6. Let C, the client data claimed as collected during the credential creation, be the result of
 *    running an implementation-specific JSON parser on JSONtext.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CompileClientDataJson extends BaseCompileClientDataJson
{
    //
}
