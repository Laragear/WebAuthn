<?php

namespace Laragear\WebAuthn;

class ClientDataJson
{
    /**
     * Create a new Client Data JSON object.
     *
     * @param  string  $type
     * @param  string  $origin
     * @param  \Laragear\WebAuthn\ByteBuffer  $challenge
     */
    public function __construct(public string $type, public string $origin, public ByteBuffer $challenge)
    {
        //
    }
}
