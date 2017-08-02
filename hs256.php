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

function generateJWT(
    string $algo,
    array $header,
    array $payload,
    string $secret
): string {
    $headerEncoded = base64UrlEncode(json_encode($header));

    $payloadEncoded = base64UrlEncode(json_encode($payload));

    // Delimit with period (.)
    $dataEncoded = "$headerEncoded.$payloadEncoded";

    $rawSignature = hash_hmac($algo, $dataEncoded, $secret, true);

    $signatureEncoded = base64UrlEncode($rawSignature);

    // Delimit with second period (.)
    $jwt = "$dataEncoded.$signatureEncoded";

    return $jwt;
}

// Highly confidential
$secret = "HIGHLY CONFIDENTIAL SECRET KEY";

// JWT Header
$header = [
    "alg"   => "HS256",
    "typ"   => "JWT"
];

// JWT Payload data
$payload = [
    "sub"       => "1234567890",
    "name"      => "John Doe",
    "admin"     => true
];

// Create the JWT
$jwt = generateJWT('sha256', $header, $payload, $secret);

var_dump($jwt); // string(149) "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.6pteLozCETeYDL9Dgm-k4INQ1oEsUf0nFy8Tn2OIxgo"

function verifyJWT(string $algo, string $jwt, string $secret): bool
{
    list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode('.', $jwt);

    $dataEncoded = "$headerEncoded.$payloadEncoded";

    $signature = base64UrlDecode($signatureEncoded);

    $rawSignature = hash_hmac($algo, $dataEncoded, $secret, true);

    return hash_equals($rawSignature, $signature);
}

$verify = verifyJWT('sha256', $jwt, $secret);

var_dump($verify);