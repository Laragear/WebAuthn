<?php

namespace Laragear\WebAuthn;

use Illuminate\Contracts\Support\Jsonable;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use JsonSerializable;
use OutOfBoundsException;
use Stringable;
use function base64_decode;
use function base64_encode;
use function bin2hex;
use function hash_equals;
use function hex2bin;
use function json_decode;
use function ord;
use function random_bytes;
use function rtrim;
use function str_repeat;
use function strlen;
use function strtr;
use function substr;
use function unpack;

/**
 * MIT License
 *
 * Copyright (c) 2018 Thomas Bleeker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
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
 * MIT License
 *
 * Copyright © 2021 Lukas Buchs
 * Copyright © 2018 Thomas Bleeker (CBOR & ByteBuffer part)
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
 * This file has been modernized to fit Laravel.
 *
 * @author Lukas Buchs
 * @author Thomas Bleeker
 * @internal
 */
class ByteBuffer implements JsonSerializable, Jsonable, Stringable
{
    /**
     * Create a new ByteBuffer
     *
     * @param  string  $binaryData
     * @param  int  $dataLength
     */
    public function __construct(protected string $binaryData, protected int $dataLength = 0)
    {
        $this->dataLength = strlen($binaryData);
    }

    /**
     * Returns the length of the ByteBuffer data.
     *
     * @return int
     */
    public function getDataLength(): int
    {
        return $this->dataLength;
    }

    /**
     * Check if the length of the data is greater than zero.
     *
     * @return bool
     */
    public function hasLength(): bool
    {
        return (bool) $this->dataLength;
    }

    /**
     * Check if the length of the data is zero.
     *
     * @return bool
     */
    public function hasNoLength(): bool
    {
        return !$this->hasLength();
    }

    /**
     * Returns the binary string verbatim.
     *
     * @return string
     */
    public function getBinaryString(): string
    {
        return $this->binaryData;
    }

    /**
     * Check if both Byte Buffers are equal using `hash_equals`.
     *
     * @param  \Laragear\WebAuthn\ByteBuffer|string  $buffer
     * @return bool
     */
    public function hashEqual(self|string $buffer): bool
    {
        if ($buffer instanceof static) {
            $buffer = $buffer->getBinaryString();
        }

        return hash_equals($this->binaryData, $buffer);
    }

    /**
     * Check if both Byte Buffers are not equal using `hash_equals`.
     *
     * @param  \Laragear\WebAuthn\ByteBuffer|string  $buffer
     * @return bool
     */
    public function hashNotEqual(self|string $buffer): bool
    {
        return ! $this->hashEqual($buffer);
    }

    /**
     * Returns a certain portion of these bytes.
     *
     * @param  int  $offset
     * @param  int|null  $length
     * @return string
     */
    public function getBytes(int $offset = 0, int $length = null): string
    {
        $length ??= $this->dataLength;

        if ($offset < 0 || $length < 0 || ($offset + $length > $this->dataLength)) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset or length.');
        }

        return substr($this->binaryData, $offset, $length);
    }

    /**
     * Returns the value of a single byte.
     *
     * @param  int  $offset
     * @return int
     */
    public function getByteVal(int $offset = 0): int
    {
        if (!$byte = $this->binaryData[$offset] ?? null) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }

        return ord($byte);
    }

    /**
     * Returns the value of a single unsigned 16-bit integer.
     *
     * @param  int  $offset
     * @return int
     */
    public function getUint16Val(int $offset = 0): int
    {
        if ($offset < 0 || ($offset + 2) > $this->dataLength) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }

        return unpack('n', $this->binaryData, $offset)[1];
    }

    /**
     * Returns the value of a single unsigned 32-bit integer.
     *
     * @param  int  $offset
     * @return int
     */
    public function getUint32Val(int $offset = 0): int
    {
        if ($offset < 0 || ($offset + 4) > $this->dataLength) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }

        $val = unpack('N', $this->binaryData, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new OutOfBoundsException('ByteBuffer: Value out of integer range.');
        }

        return $val;
    }

    /**
     * Returns the value of a single unsigned 64-bit integer.
     *
     * @param  int  $offset
     * @return int
     */
    public function getUint64Val(int $offset): int
    {
        if (PHP_INT_SIZE < 8) {
            throw new OutOfBoundsException('ByteBuffer: 64-bit values not supported by this system');
        }

        if ($offset < 0 || ($offset + 8) > $this->dataLength) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }

        $val = unpack('J', $this->binaryData, $offset)[1];

        // Signed integer overflow causes signed negative numbers
        if ($val < 0) {
            throw new OutOfBoundsException('ByteBuffer: Value out of integer range.');
        }

        return $val;
    }

    /**
     * Returns the value of a single 16-bit float.
     *
     * @param  int  $offset
     * @return float
     */
    public function getHalfFloatVal(int $offset = 0): float
    {
        // FROM spec pseudo decode_half(unsigned char *halfp)
        $half = $this->getUint16Val($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    /**
     * Returns the value of a single 32-bit float.
     *
     * @param  int  $offset
     * @return float
     */
    public function getFloatVal(int $offset = 0): float
    {
        if ($offset < 0 || ($offset + 4) > $this->dataLength) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }

        return unpack('G', $this->binaryData, $offset)[1];
    }

    /**
     * Returns the value of a single 64-bit float.
     *
     * @param  int  $offset
     * @return float
     */
    public function getDoubleVal(int $offset = 0): float
    {
        if ($offset < 0 || ($offset + 8) > $this->dataLength) {
            throw new InvalidArgumentException('ByteBuffer: Invalid offset');
        }
        return unpack('E', $this->binaryData, $offset)[1];
    }

    /**
     * Transforms the ByteBuffer JSON into a generic Object.
     *
     * @param  int  $jsonFlags
     * @return object
     * @throws \JsonException
     */
    public function toObject(int $jsonFlags = 0): object
    {
        return json_decode($this->binaryData, null, 512, JSON_THROW_ON_ERROR | $jsonFlags);
    }

    /**
     * Returns a Base64 URL representation of the byte buffer.
     *
     * @return string
     */
    public function toBase64Url(): string
    {
        return static::encodeBase64Url($this->binaryData);
    }

    /**
     * Specify data which should be serialized to JSON.
     *
     * @return string
     */
    public function jsonSerialize(): string
    {
        return $this->toBase64Url();
    }

    /**
     * Returns a hexadecimal representation of the ByteBuffer.
     *
     * @return string
     */
    public function toHex(): string
    {
        return bin2hex($this->binaryData);
    }

    /**
     * object to string
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->toHex();
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     * @return string
     */
    public function toJson($options = 0): string
    {
        return $this->jsonSerialize();
    }

    /**
     * Returns an array of data for serialization.
     *
     * @return array
     */
    #[ArrayShape(['binaryData' => "string"])]
    public function __serialize(): array
    {
        return ['binaryData' => static::encodeBase64Url($this->binaryData)];
    }

    /**
     * Serializable-Interface
     *
     * @param  array  $data
     */
    public function __unserialize(array $data): void
    {
        $this->binaryData = static::decodeBase64Url($data['binaryData']);
        $this->dataLength = strlen($this->binaryData);
    }

    /**
     * Create a ByteBuffer from a BASE64 URL encoded string.
     *
     * @param  string  $base64url
     * @return static
     */
    public static function fromBase64Url(string $base64url): static
    {
        if (false === $bin = self::decodeBase64Url($base64url)) {
            throw new InvalidArgumentException('ByteBuffer: Invalid base64 url string');
        }

        return new ByteBuffer($bin);
    }

    /**
     * Create a ByteBuffer from a BASE64 encoded string.
     *
     * @param  string  $base64
     * @return static
     */
    public static function fromBase64(string $base64): static
    {
        if (false === $bin = base64_decode($base64)) {
            throw new InvalidArgumentException('ByteBuffer: Invalid base64 string');
        }

        return new ByteBuffer($bin);
    }

    /**
     * Create a ByteBuffer from a hexadecimal string.
     *
     * @param  string  $hex
     * @return static
     */
    public static function fromHex(string $hex): static
    {
        if (false === $bin = hex2bin($hex)) {
            throw new InvalidArgumentException('ByteBuffer: Invalid hex string');
        }

        return new static($bin);
    }

    /**
     * Create a random ByteBuffer
     *
     * @param  int  $length
     * @return static
     */
    public static function makeRandom(int $length): static
    {
        return new static(random_bytes($length));
    }

    /**
     * Decodes a BASE64 URL string.
     *
     * @param  string  $data
     * @return string|false
     */
    protected static function decodeBase64Url(string $data): string|false
    {
        return base64_decode(strtr($data, '-_', '+/').str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }

    /**
     * Encodes a BASE64 URL string.
     *
     * @param  string  $data
     * @return string|false
     */
    protected static function encodeBase64Url(string $data): string|false
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
