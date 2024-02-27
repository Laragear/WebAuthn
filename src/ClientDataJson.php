<?php

namespace Laragear\WebAuthn;

class ClientDataJson
{
    /**
     * Create a new Client Data JSON object.
     */
    public function __construct(public string $type, public string $origin, public ByteBuffer $challenge)
    {
        //
    }
}
