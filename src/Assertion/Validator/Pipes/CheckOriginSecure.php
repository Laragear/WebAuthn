<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Laragear\WebAuthn\SharedPipes\CheckOriginSecure as BaseCheckOriginSame;

/**
 * 9. Verify that the value of C.origin matches the Relying Party's origin.
 *
 * @internal
 */
class CheckOriginSecure extends BaseCheckOriginSame
{
    //
}
