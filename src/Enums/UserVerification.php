<?php

namespace Laragear\WebAuthn\Enums;

enum UserVerification: string
{
    case Preferred = 'preferred';
    case Discouraged = 'discouraged';
    case Required = 'required';
}
