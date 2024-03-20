<?php

namespace Laragear\WebAuthn;

use InvalidArgumentException;
use Laragear\WebAuthn\Exceptions\DataException;

use function is_int;
use function is_string;
use function sprintf;

/**
 * MIT License.
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
 * Copyright (c) 2021 Lukas Buchs
 * Copyright (c) 2018 Thomas Bleeker (CBOR & ByteBuffer part)
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
 *
 * @internal
 */
class CborDecoder
{
    public const CBOR_MAJOR_UNSIGNED_INT = 0;
    public const CBOR_MAJOR_TEXT_STRING = 3;
    public const CBOR_MAJOR_FLOAT_SIMPLE = 7;
    public const CBOR_MAJOR_NEGATIVE_INT = 1;
    public const CBOR_MAJOR_ARRAY = 4;
    public const CBOR_MAJOR_TAG = 6;
    public const CBOR_MAJOR_MAP = 5;
    public const CBOR_MAJOR_BYTE_STRING = 2;

    /**
     * Decodes the binary data.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    public static function decode(ByteBuffer|string $encoded): ByteBuffer|array|bool|float|int|string|null
    {
        if (is_string($encoded)) {
            $encoded = new ByteBuffer($encoded);
        }

        $offset = 0;

        $result = static::parseItem($encoded, $offset);

        if ($offset !== $encoded->getDataLength()) {
            throw new DataException('CBOR: Unused bytes after data item.');
        }

        return $result;
    }

    /**
     * Decodes a portion of the Byte Buffer.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    public static function decodePortion(ByteBuffer|string $bufOrBin, int $startOffset, ?int &$endOffset = null): ByteBuffer|array|bool|float|int|string|null
    {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = $startOffset;
        $data = static::parseItem($buf, $offset);
        $endOffset = $offset;

        return $data;
    }

    /**
     * Parses a single item of the Byte Buffer.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseItem(ByteBuffer $buf, int &$offset): ByteBuffer|array|bool|float|int|string|null
    {
        $first = $buf->getByteVal($offset++);
        $type = $first >> 5;
        $val = $first & 0b11111;

        if ($type === static::CBOR_MAJOR_FLOAT_SIMPLE) {
            return static::parseFloatSimple($val, $buf, $offset);
        }

        $val = static::parseExtraLength($val, $buf, $offset);

        try {
            return static::parseItemData($type, $val, $buf, $offset);
        } catch (InvalidArgumentException $e) {
            throw new DataException($e->getMessage());
        }
    }

    /**
     * Parses a simple float value.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseFloatSimple(int $val, ByteBuffer $buf, int &$offset): bool|float|null
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;

                return static::parseSimpleValue($val);
            case 25:
                $floatValue = $buf->getHalfFloatVal($offset);
                $offset += 2;

                return $floatValue;
            case 26:
                $floatValue = $buf->getFloatVal($offset);
                $offset += 4;

                return $floatValue;
            case 27:
                $floatValue = $buf->getDoubleVal($offset);
                $offset += 8;

                return $floatValue;
            case 28:
            case 29:
            case 30:
                throw new DataException('Reserved value used.');
            case 31:
                throw new DataException('Indefinite length is not supported.');
            default:
                return static::parseSimpleValue($val);
        }
    }

    /**
     * Parses a simple value from CBOR.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseSimpleValue(int $val): ?bool
    {
        return match ($val) {
            20 => false,
            21 => true,
            22 => null,
            default => throw new DataException(sprintf('Unsupported simple value %d.', $val))
        };
    }

    /**
     * Parses the CBOR extra length.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseExtraLength(int $val, ByteBuffer $buf, int &$offset): int
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;

                return $val;
            case 25:
                $val = $buf->getUint16Val($offset);
                $offset += 2;

                return $val;
            case 26:
                $val = $buf->getUint32Val($offset);
                $offset += 4;

                return $val;
            case 27:
                $val = $buf->getUint64Val($offset);
                $offset += 8;

                return $val;
            case 28:
            case 29:
            case 30:
                throw new DataException('Reserved value used.');
            case 31:
                throw new DataException('Indefinite length is not supported.');
            default:
                return $val;
        }
    }

    /**
     * Parses the data inside a Byte Buffer.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException|\InvalidArgumentException
     */
    protected static function parseItemData(
        int $type,
        int $val,
        ByteBuffer $buf,
        &$offset
    ): ByteBuffer|array|bool|float|int|string|null {
        switch ($type) {
            case static::CBOR_MAJOR_UNSIGNED_INT: // uint
                return $val;

            case static::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $val;

            case static::CBOR_MAJOR_BYTE_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;

                return new ByteBuffer($data); // bytes

            case static::CBOR_MAJOR_TEXT_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;

                return $data; // UTF-8

            case static::CBOR_MAJOR_ARRAY:
                return static::parseArray($buf, $offset, $val);

            case static::CBOR_MAJOR_MAP:
                return static::parseMap($buf, $offset, $val);

            case static::CBOR_MAJOR_TAG:
                return static::parseItem($buf, $offset); // 1 embedded data item
        }

        throw new DataException(sprintf('Unknown major type %d.', $type));
    }

    /**
     * Parses an array with string keys.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseMap(ByteBuffer $buffer, int &$offset, int $count): array
    {
        $map = [];

        for ($i = 0; $i < $count; $i++) {
            $mapKey = static::parseItem($buffer, $offset);
            $mapVal = static::parseItem($buffer, $offset);

            if (! is_int($mapKey) && ! is_string($mapKey)) {
                throw new DataException('Can only use strings or integers as map keys');
            }

            $map[$mapKey] = $mapVal;
        }

        return $map;
    }

    /**
     * Parses an array from the byte buffer.
     *
     * @throws \Laragear\WebAuthn\Exceptions\DataException
     */
    protected static function parseArray(ByteBuffer $buf, int &$offset, int $count): array
    {
        $arr = [];

        for ($i = 0; $i < $count; $i++) {
            $arr[] = static::parseItem($buf, $offset);
        }

        return $arr;
    }
}
