<?php

namespace Laragear\WebAuthn\Enums;

enum Transport: string
{
    case SMART_CARD = 'smart-card';
    case INTERNAL = 'internal';
    case HYBRID = 'hybrid';
    case USB = 'usb';
    case NFC = 'nfc';
    case BLE = 'ble';
}
