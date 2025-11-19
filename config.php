<?php
return [
    // LICENSE_CHECK=false in environment disables runtime license validation for local/dev
    'license_check' => (function () {
        $envValue = getenv('LICENSE_CHECK');
        if ($envValue === false || $envValue === null || $envValue === '') {
            return true;
        }
        $normalized = strtolower(trim($envValue));
        return !in_array($normalized, ['0', 'false', 'off', 'no'], true);
    })(),
];
