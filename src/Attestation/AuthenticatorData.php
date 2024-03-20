<?php

namespace Laragear\WebAuthn\Attestation;

use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\CborDecoder;
use Laragear\WebAuthn\Exceptions\DataException;
use function base64_encode;
use function chr;
use function chunk_split;
use function intdiv;
use function is_array;
use function ord;
use function strlen;
use function substr;
use function unpack;

/**
 * MIT License.
 *
 * Copyright (c) 2021 Lukas Buchs
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
 *
 * This file has been modernized to fit Laravel.
 *
 * @author Lukas Buchs
 *
 * @internal
 *
 * DER = Distinguished Encoding Rules;
 * PEM = Privacy Enhanced Mail, basically BASE64 encoded DER.
 */
class AuthenticatorData
{
    // COSE encoded keys
    protected const COSE_KTY = 1;
    protected const COSE_ALG = 3;

    // COSE EC2 ES256 P-256 curve
    protected const COSE_CRV = -1;
    protected const COSE_X = -2;
    protected const COSE_Y = -3;

    // COSE RSA PS256
    protected const COSE_N = -1;
    protected const COSE_E = -2;

    // EC2
    protected const EC2_TYPE = 2;
    protected const EC2_P256 = 1;
    public const EC2_ES256 = -7;

    // RSA
    protected const RSA_TYPE = 3;
    public const RSA_RS256 = -257;

    // OKP
    protected const OKP_TYPE = 1;
    protected const OKP_ED25519 = 6;
    public const OKP_EDDSA = -8;

    /**
     * Creates a new Authenticator Data instance from a binary string.
     */
    final public function __construct(
        public string $relyingPartyIdHash,
        public object $flags,
        public int $counter,
        public object $attestedCredentialData,
        public array $extensionData,
    ) {
        //
    }

    /**
     * Checks if the Relying Party ID hash is the same as the one issued.
     */
    public function hasSameRPIdHash(string $relyingPartyId, bool $hash = true): bool
    {
        if ($hash) {
            $relyingPartyId = hash('sha256', $relyingPartyId, true);
        }

        return hash_equals($relyingPartyId, $this->relyingPartyIdHash);
    }

    /**
     * Checks if the Relying Party ID hash is not the same as the one issued.
     */
    public function hasNotSameRPIdHash(string $relyingPartyId, bool $hash = true): bool
    {
        return ! $this->hasSameRPIdHash($relyingPartyId, $hash);
    }

    /**
     * Check if the user was present during the authentication.
     */
    public function wasUserPresent(): bool
    {
        return $this->flags->userPresent;
    }

    /**
     * Check if the user was absent during the authentication.
     */
    public function wasUserAbsent(): bool
    {
        return ! $this->wasUserPresent();
    }

    /**
     * Check if the user was actively verified by the authenticator.
     */
    public function wasUserVerified(): bool
    {
        return $this->flags->userVerified;
    }

    /**
     * Check if the user was not actively verified by the authenticator.
     */
    public function wasUserNotVerified(): bool
    {
        return ! $this->wasUserVerified();
    }

    /**
     * Returns the public key in PEM format.
     */
    public function getPublicKeyPem(): string
    {
        $der = match ($this->attestedCredentialData->credentialPublicKey->kty) {
            static::EC2_TYPE => $this->getEc2Der(),
            static::RSA_TYPE => $this->getRsaDer(),
            static::OKP_TYPE => $this->getOkpDer(),
            default => throw new DataException('Invalid credential public key type [kty].'),
        };

        return
            '-----BEGIN PUBLIC KEY-----'.
            "\n".chunk_split(base64_encode($der), 64, "\n").
            '-----END PUBLIC KEY-----'.
            "\n";
    }

    /**
     * Returns the public key in U2F format.
     */
    public function getPublicKeyU2F(): string
    {
        return "\x04". // ECC uncompressed
            $this->attestedCredentialData->credentialPublicKey->x.
            $this->attestedCredentialData->credentialPublicKey->y;
    }

    /**
     * Returns DER encoded EC2 key.
     */
    protected function getEc2Der(): string
    {
        return $this->derSequence(
            $this->derSequence(
                $this->derOid("\x2A\x86\x48\xCE\x3D\x02\x01"). // OID 1.2.840.10045.2.1 ecPublicKey
                $this->derOid("\x2A\x86\x48\xCE\x3D\x03\x01\x07")  // 1.2.840.10045.3.1.7 prime256v1
            ).
            $this->derBitString($this->getPublicKeyU2F())
        );
    }

    /**
     * Returns DER encoded RSA key.
     */
    protected function getRsaDer(): string
    {
        return $this->derSequence(
            $this->derSequence(
                $this->derOid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"). // OID 1.2.840.113549.1.1.1 rsaEncryption
                $this->derNullValue()
            ).
            $this->derBitString(
                $this->derSequence(
                    $this->derUnsignedInteger($this->attestedCredentialData->credentialPublicKey->n).
                    $this->derUnsignedInteger($this->attestedCredentialData->credentialPublicKey->e)
                )
            )
        );
    }

    /**
     * Returns KPE encoded EdDSA key.
     */
    protected function getOkpDer(): string
    {
        return $this->derSequence(
            $this->derSequence(
                $this->derOid("\x2B\x65\x70") // OID 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
            ).
            $this->derBitString($this->attestedCredentialData->credentialPublicKey->x)
        );
    }

    /**
     * Returns the length of a DER encoded string.
     */
    protected function derLength(int $der): string
    {
        if ($der < 128) {
            return chr($der);
        }

        $lenBytes = '';

        while ($der > 0) {
            $lenBytes = chr($der % 256).$lenBytes;
            $der = intdiv($der, 256);
        }

        return chr(0x80 | strlen($lenBytes)).$lenBytes;
    }

    /**
     * Encode a string as DER.
     */
    protected function derSequence(string $contents): string
    {
        return "\x30".$this->derLength(strlen($contents)).$contents;
    }

    /**
     * Encode something an ID of zero as DER.
     */
    protected function derOid(string $encoded): string
    {
        return "\x06".$this->derLength(strlen($encoded)).$encoded;
    }

    /**
     * Encode the bit string as DER.
     */
    protected function derBitString(string $bytes): string
    {
        return "\x03".$this->derLength(strlen($bytes) + 1)."\x00".$bytes;
    }

    /**
     * Encode a null value as DER.
     */
    protected function derNullValue(): string
    {
        return "\x05\x00";
    }

    /**
     * Encode a unsigned integer as DER.
     */
    protected function derUnsignedInteger(string $bytes): string
    {
        $len = strlen($bytes);

        // Remove leading zero bytes
        for ($i = 0; $i < ($len - 1); $i++) {
            if (ord($bytes[$i]) !== 0) {
                break;
            }
        }
        if ($i !== 0) {
            $bytes = substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero to prevent it being seen as negative number
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".$this->derLength(strlen($bytes)).$bytes;
    }

    /**
     * Create a new Authenticator data from a binary string.
     *
     * @codeCoverageIgnore
     */
    public static function fromBinary(string $binary): static
    {
        if (strlen($binary) < 37) {
            throw new DataException('Authenticator Data: Invalid input.');
        }

        $relyingPartyIdHash = substr($binary, 0, 32);

        // flags (1 byte)
        $flags = static::readFlags(unpack('Cflags', $binary[32])['flags']);

        // signature counter: 32-bit unsigned big-endian integer.
        $counter = unpack('Nsigncount', substr($binary, 33, 4))['signcount'];

        $offset = 37;

        $attestedCredentialData = $flags->attestedDataIncluded
            ? static::readAttestData($binary, $offset)
            : (object) null;

        $extensionData = $flags->extensionDataIncluded
            ? static::readExtensionData(substr($binary, $offset))
            : [];

        return new static($relyingPartyIdHash, $flags, $counter, $attestedCredentialData, $extensionData);
    }

    /**
     * Reads the flags from flag byte array.
     *
     * @return object{userPresent: bool, userVerified: bool, attestedDataIncluded: bool, extensionDataIncluded: bool}
     */
    protected static function readFlags(string $binFlag): object
    {
        $flags = (object) [
            // @phpstan-ignore-next-line
            'bit_0' => (bool) ($binFlag & 1),
            // @phpstan-ignore-next-line
            'bit_1' => (bool) ($binFlag & 2),
            // @phpstan-ignore-next-line
            'bit_2' => (bool) ($binFlag & 4),
            // @phpstan-ignore-next-line
            'bit_3' => (bool) ($binFlag & 8),
            // @phpstan-ignore-next-line
            'bit_4' => (bool) ($binFlag & 16),
            // @phpstan-ignore-next-line
            'bit_5' => (bool) ($binFlag & 32),
            // @phpstan-ignore-next-line
            'bit_6' => (bool) ($binFlag & 64),
            // @phpstan-ignore-next-line
            'bit_7' => (bool) ($binFlag & 128),
            'userPresent' => false,
            'userVerified' => false,
            'attestedDataIncluded' => false,
            'extensionDataIncluded' => false,
        ];

        // named flags
        $flags->userPresent = $flags->bit_0;
        $flags->userVerified = $flags->bit_2;
        $flags->attestedDataIncluded = $flags->bit_6;
        $flags->extensionDataIncluded = $flags->bit_7;

        return $flags;
    }

    /**
     * Reads the attestation data.
     *
     * @return object{aaguid: string, credentialId: \Laragear\WebAuthn\ByteBuffer, credentialPublicKey: object}&\stdClass
     */
    protected static function readAttestData(string $binary, int &$endOffset): object
    {
        if (strlen($binary) <= 55) {
            throw new DataException('Attested data is missing');
        }

        // Byte length L of Credential ID, 16-bit unsigned big-endian integer.
        $length = unpack('nlength', substr($binary, 53, 2))['length'];

        // Set end offset.
        $endOffset = 55 + $length;

        return (object) [
            'aaguid' => substr($binary, 37, 16),
            'credentialId' => new ByteBuffer(substr($binary, 55, $length)),
            'credentialPublicKey' => static::readCredentialPublicKey($binary, 55 + $length, $endOffset),
        ];
    }

    /**
     * Read COSE key-encoded elliptic curve public key in EC2 format.
     */
    protected static function readCredentialPublicKey(string $binary, int $offset, int &$endOffset): object
    {
        $enc = CborDecoder::decodePortion($binary, $offset, $endOffset);

        // COSE key-encoded elliptic curve public key in EC2 format
        $publicKey = (object) [
            'kty' => $enc[static::COSE_KTY],
            'alg' => $enc[static::COSE_ALG],
        ];

        match ($publicKey->alg) {
            static::EC2_ES256 => static::readCredentialPublicKeyES256($publicKey, $enc),
            static::RSA_RS256 => static::readCredentialPublicKeyRS256($publicKey, $enc),
            static::OKP_EDDSA => static::readCredentialPublicKeyEDDSA($publicKey, $enc),
            default => throw new DataException("The $publicKey->alg algorithm is not supported.")
        };

        return $publicKey;
    }

    /**
     * Extracts ES256 information from COSE encoding.
     */
    protected static function readCredentialPublicKeyES256(object $publicKey, array $cose): object
    {
        $publicKey->crv = $cose[static::COSE_CRV];
        $publicKey->x = $cose[static::COSE_X] instanceof ByteBuffer ? $cose[static::COSE_X]->getBinaryString() : null;
        $publicKey->y = $cose[static::COSE_Y] instanceof ByteBuffer ? $cose[static::COSE_Y]->getBinaryString() : null;

        if ($publicKey->kty !== static::EC2_TYPE) {
            throw new DataException('Public key not in EC2 format');
        }

        if ($publicKey->alg !== static::EC2_ES256) {
            throw new DataException('Signature algorithm not ES256');
        }

        if ($publicKey->crv !== static::EC2_P256) {
            throw new DataException('Curve not P-256');
        }

        if (strlen($publicKey->x) !== 32) {
            throw new DataException('Invalid X-coordinate');
        }

        if (strlen($publicKey->y) !== 32) {
            throw new DataException('Invalid Y-coordinate');
        }

        return $publicKey;
    }

    /**
     * Extract RS256 information from COSE.
     */
    protected static function readCredentialPublicKeyRS256(object $publicKey, array $enc): void
    {
        $publicKey->n = $enc[static::COSE_N] instanceof ByteBuffer ? $enc[static::COSE_N]->getBinaryString() : null;
        $publicKey->e = $enc[static::COSE_E] instanceof ByteBuffer ? $enc[static::COSE_E]->getBinaryString() : null;

        if ($publicKey->kty !== static::RSA_TYPE) {
            throw new DataException('Public key not in RSA format');
        }

        if ($publicKey->alg !== static::RSA_RS256) {
            throw new DataException('Signature algorithm not ES256');
        }

        if (strlen($publicKey->n) !== 256) {
            throw new DataException('Invalid RSA modulus');
        }

        if (strlen($publicKey->e) !== 3) {
            throw new DataException('Invalid RSA public exponent');
        }
    }

    /**
     * Extract EdDSA information from COSE.
     */
    protected static function readCredentialPublicKeyEDDSA(object $publicKey, array $enc): void
    {
        $publicKey->crv = $enc[static::COSE_CRV];
        $publicKey->x = $enc[static::COSE_X] instanceof ByteBuffer ? $enc[static::COSE_X]->getBinaryString() : null;

        if ($publicKey->kty !== static::OKP_TYPE) {
            throw new DataException('Public key not in OKP format');
        }

        if ($publicKey->alg !== static::OKP_EDDSA) {
            throw new DataException('Signature algorithm not EdDSA');
        }

        if ($publicKey->crv !== static::OKP_ED25519) {
            throw new DataException('Curve not Ed25519');
        }

        if (strlen($publicKey->x) !== 32) {
            throw new DataException('Invalid X coordinate for Ed25519 curve.');
        }
    }

    /**
     * Reads CBOR encoded extension data.
     */
    protected static function readExtensionData(string $binary): array
    {
        $ext = CborDecoder::decode($binary);

        return is_array($ext) ? $ext : throw new DataException('Invalid extension data');
    }
}
