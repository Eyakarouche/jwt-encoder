<?php

namespace SymfonyJwtEncoderLibrary;

use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Firebase\JWT\JWT;

class JwtEncoderService
{
    private $jwtTokenManager;
    private $secretKey;
    private $expiration;

    private $algo='HS256';
    public function __construct(JWTTokenManagerInterface $jwtTokenManager, string $secretKey, int $expiration)
    {
        $this->jwtTokenManager = $jwtTokenManager;
        $this->secretKey = $secretKey;
        $this->expiration = $expiration;
    }

    public function encodePassword(string $plainPassword): string
    {
        $payload = [
            'iss' => $_SERVER['SERVER_NAME'],
            'exp' => $_SERVER['REQUEST_TIME'] + $this->expiration,
            'psKey' => sha1($plainPassword),
        ];
        return JWT::encode($payload, $this->secretKey, $this->algo);

    }

    public function decodePassword(string $encodedPassword): array
    {
        try {
            $decoded = JWT::decode($encodedPassword, $this->secretKey, $this->algo);

            if (!isset($decoded->iss, $decoded->exp, $decoded->psKey)) {
                throw new \UnexpectedValueException('Invalid JWT payload structure');
            }
            if ($decoded->exp < time()) {
                throw new \Exception('Token has expired');
            }

            return [
                'issuer' => $decoded->iss,
                'expiration' => $decoded->exp,
                'psKey' => $decoded->psKey,
            ];
        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to decode password', 0, $e);
        }
    }

}
