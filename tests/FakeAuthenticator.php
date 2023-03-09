<?php

namespace Tests;

use JetBrains\PhpStorm\ArrayShape;

class FakeAuthenticator
{
    public const CREDENTIAL_ID = 'owBYu_waGLhAOCg4EFzi6Lr55x51G2dR5yhJi8q2C3tgZQQL2aEi-nK3I54J6ILj70pJzR_6QxvA5XER17d7NA9EFe2QH3VoJYQGpO8G5yDoFQvsdkxNhioyMyhyQHNrAgTMGyfigIMCfhjk9te7LNYl9K5GbWRc4TGeQl1vROjBtTNm3GdpEOqp9RijWd-ShQZ95eHoc8SA_-8vzCyfmy-wI_K4ZqlQNNl85Fzg2GIBcC2zvcJhLYy1A2kw6JoBTAmz1ZCCgkTKWhzUvAJQpMpu40M67FqE0WkGZfSJ9A';
    public const CREDENTIAL_ID_RAW = 'owBYu/waGLhAOCg4EFzi6Lr55x51G2dR5yhJi8q2C3tgZQQL2aEi+nK3I54J6ILj70pJzR/6QxvA5XER17d7NA9EFe2QH3VoJYQGpO8G5yDoFQvsdkxNhioyMyhyQHNrAgTMGyfigIMCfhjk9te7LNYl9K5GbWRc4TGeQl1vROjBtTNm3GdpEOqp9RijWd+ShQZ95eHoc8SA/+8vzCyfmy+wI/K4ZqlQNNl85Fzg2GIBcC2zvcJhLYy1A2kw6JoBTAmz1ZCCgkTKWhzUvAJQpMpu40M67FqE0WkGZfSJ9A=';

    public const ATTESTATION_USER = [
        'id' => 'e8af6f703f8042aa91c30cf72289aa07',
        'name' => 'john@doe.com',
        'displayName' => 'John Doe',
    ];

    public const ATTESTATION_CHALLENGE = 'H04uZbKiqSx+xEcJ7TIYDg==';
    public const ASSERTION_CHALLENGE = 'iXozmynKi+YD2iRvKNbSPA==';

    /**
     * Returns a correct attestation response.
     *
     * @return array
     */
    #[ArrayShape(['id' => "string", 'type' => "string", 'rawId' => "string", 'response' => "string[]"])]
    public static function attestationResponse(): array
    {
        return [
            'id' => static::CREDENTIAL_ID,
            'type' => 'public-key',
            'rawId' => static::CREDENTIAL_ID_RAW,
            'response' => [
                'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSDA0dVpiS2lxU3gteEVjSjdUSVlEZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==',
                'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACD5U4sUo9j78W4wj+wnuAyWUrvovdWhFQg2PqUv9neoOKQBAwM5AQAgWQEAnBadZo+CnNdUHvzCWuLNTFsXTCjsHH5A+aUtIImsJsbTKmYsYtOuiOwEgcGglKEJV0MwzV4v2SDQzSirwLErisis4qV6Q3a0ZyZcYhgyMzvkk5CtDhpzxhsmFwiMSGt9gVRE8cOxGDQX2jTPfqykxZTkoXKEHevq8kl5PBCPsaWskrWsySw9mmqNCmIjhE2Evgarm0Xq7yq5h62H2ZzFT3U5C0H32I9cTPk6f/SVke+GMseVRiLleltJMNl0C0cKGBmJpQfeLFlKmOc15WqlwuMegjGULD9dPQvZS5uX+P0bHYfXq5V/HTwrR9FmkEdhq5YB9nE6RkE6Fbs5f+LIhSFDAQAB',
            ],
        ];
    }

    /**
     * Returns a correct Assertion response.
     *
     * @return array
     */
    #[ArrayShape(['id' => "string", 'type' => "string", 'rawId' => "string", 'response' => "string[]"])]
    public static function assertionResponse(): array
    {
        return [
            'id' => static::CREDENTIAL_ID,
            'type' => 'public-key',
            'rawId' => static::CREDENTIAL_ID_RAW,
            'response' => [
                'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVhvem15bktpLVlEMmlSdktOYlNQQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
                'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAQ==',
                'signature' => 'ca4IJ9h8bZnjMbEFuHX1zfX5LcbiPyDVz6sD1/ppR4t8++1DxKa5EdBIrfNlo8FSOv/JSzMrGGUCQvc/Ngj1KnZpO3s9OdTb54/gMDewH/K8EG4wSvxzHdL6sMbP7UUc5Wq1pcdu9MgXY8V+1gftXpzcoaae0X+mLEETgU7eB8jG0mZhVWvE4yQKuDnZA1i9r8oQhqsvG4nUw1BxvR8wAGiRR+R287LaL41k+xum5mS8zEojUmuLSH50miyVxZ4Y+/oyfxG7i+wSYGNSXlW5iNPB+2WupGS7ce4TuOgaFeMmP2a9rzP4m2IBSQoJ2FyrdzR7HwBEewqqrUVbGQw3Aw==',
                'userHandle' => static::ATTESTATION_USER['id'],
            ],
        ];
    }
}
