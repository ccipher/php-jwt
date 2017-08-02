<?php

function base64UrlEncode(string $data): string
{
    $urlSafeData = strtr(base64_encode($data), '+/', '-_');

    return rtrim($urlSafeData, '='); 
} 

function base64UrlDecode(string $data): string
{
    $urlUnsafeData = strtr($data, '-_', '+/');

    $paddedData = str_pad($urlUnsafeData, strlen($data) % 4, '=', STR_PAD_RIGHT);

    return base64_decode($paddedData);
}

function getOpenSSLErrors()
{
    $messages = [];

    while ($msg = openssl_error_string()) {
        $messages[] = $msg;
    }

    return $messages;
}

function generateJWT(
    string $algo,
    array $header,
    array $payload,
    string $privateKeyFile
): string {
    $headerEncoded = base64UrlEncode(json_encode($header));

    $payloadEncoded = base64UrlEncode(json_encode($payload));

    // Delimit with period (.)
    $dataEncoded = "$headerEncoded.$payloadEncoded";

    $privateKey = "file://".$privateKeyFile;

    $privateKeyResource = openssl_pkey_get_private($privateKey);

    $result = openssl_sign($dataEncoded, $signature, $privateKeyResource, $algo);

    if ($result === false)
    {
        throw new RuntimeException("Failed to generate signature: ".implode("\n", getOpenSSLErrors()));
    }

    $signatureEncoded = base64UrlEncode($signature);

    $jwt = "$dataEncoded.$signatureEncoded";

    return $jwt;
}

// Highly confidential
$privateKeyFile = "private.key";

// Shared with clients for signature verification
$publicKeyFile = "public.key";

// JWT Header
$header = [
    "alg"   => "RS256",
    "typ"   => "JWT"
];

// JWT Payload data
$payload = [
    "sub"       => "1234567890",
    "name"      => "John Doe",
    "admin"     => true
];

// Create the JWT
$jwt = generateJWT('sha256', $header, $payload, $privateKeyFile);

var_dump($jwt); // string(277) "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.R-41ycm1V7Kvx_Lnw6nha6OAFQ-vYvdhAdgqa1Ugkj17X4dpSWSO0KRCmnq7yd6ZM-RLEMY3PEXyUAs4F1XtomT6M-CziCpIB5piLfYHLG6V1_FrtieuIOMGLZGs-PpqMZX-JgJf_L19Ly9jnqGjfl9zo6BTTandhgNECE7AVk0"

function verifyJWT(string $algo, string $jwt, string $publicKeyFile): bool
{
    list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode('.', $jwt);

    $dataEncoded = "$headerEncoded.$payloadEncoded";

    $signature = base64UrlDecode($signatureEncoded);

    $publicKey = "file://".$publicKeyFile;

    $publicKeyResource = openssl_pkey_get_public($publicKey);

    $result = openssl_verify($dataEncoded, $signature, $publicKeyResource, $algo);

    if ($result === -1)
    {
        throw new RuntimeException("Failed to verify signature: ".implode("\n", getOpenSSLErrors()));
    }

    return (bool) $result;
}

$verify = verifyJWT('sha256', $jwt, $publicKeyFile);

var_dump($verify);