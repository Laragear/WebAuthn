<?php

namespace Laragear\WebAuthn\Attestation\Formats;

use Laragear\WebAuthn\Attestation\AuthenticatorData;

/**
 * MIT License.
 *
 * Copyright (c) 2021 Lukas Buchs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * ---
 *
 * This is a base class that hold common tasks for different Attestation Statements formats.
 *
 * This file has been modernized to fit Laravel.
 *
 * @author Lukas Buchs
 *
 * @see https://www.iana.org/assignments/webauthn/webauthn.xhtml
 *
 * @internal
 */
abstract class Format
{
    /**
     * Create a new Attestation Format.
     *
     * @param  array{fmt: string, attStmt: array, authData: \Laragear\WebAuthn\ByteBuffer}  $attestationObject
     */
    public function __construct(public array $attestationObject, public AuthenticatorData $authenticatorData)
    {
        //
    }
}
