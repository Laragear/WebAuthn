<?php

namespace Laragear\WebAuthn\Enums;

enum Transport: string
{
    case SmartCard = 'smart-card';
    case Internal = 'internal';
    case Hybrid = 'hybrid';
    case Usb = 'usb';
    case Nfc = 'nfc';
    case Ble = 'ble';
}
