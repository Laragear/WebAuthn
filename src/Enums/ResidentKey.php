<?php

namespace Laragear\WebAuthn\Enums;

enum ResidentKey: string
{
    case Required = 'required';
    case Preferred = 'preferred';
    case Discouraged = 'discouraged';
}
