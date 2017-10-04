<?php
/*
 * This file is part of the BrandOriented package.
 *
 * (c) Brand Oriented sp. z o.o.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author Dominik Labudzinski <dominik@labudzinski.com>
 * @name StrongPasswordEncoder.php - 04-10-2017 08:38
 */

namespace Metromix\PasswordEncoderBundle\Security\Encoder;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class StrongPasswordEncoder
 * @package Security\Encoder
 */
class StrongPasswordEncoder implements PasswordEncoderInterface
{
    const HASH_ALGORITHM = 'sha512';
    /**
     * @var string
     */
    private $salt;
    /**
     * @var int
     */
    private $cost = 12;

    /**
     * Constructor.
     *
     * @param int $cost
     * @param string $salt
     */
    public function __construct($cost, $salt)
    {
        if((int)$cost > 0) {
            $this->cost = $cost;
        }

        if($salt === null) {
            throw new InvalidArgumentException('Salt can not be empty.');
        }
        $this->salt = $salt;
        if(function_exists('\Sodium\library_version_major') !== true) {
            throw new AuthenticationServiceException('Libsodium doesn\'t exist.');
        }
    }

    /**
     * Encodes the raw password.
     *
     * @param string $raw  The password to encode
     * @param string $salt The salt
     *
     * @return string The encoded password
     *
     * @throws BadCredentialsException when the given password is too long
     *
     * @see http://lxr.php.net/xref/PHP_5_5/ext/standard/password.c#111
     */
    public function encodePassword($raw, $salt)
    {
        /**
         * Add salt to password
         */
        $raw = sprintf("pass_%s_%s", $raw, $salt);
        /**
         * Create sha512 hash - always have same length
         */
        $raw = hash(self::HASH_ALGORITHM, $raw);
        /**
         * Hash by bcrypt with $cost
         */
        $raw = password_hash($raw, PASSWORD_BCRYPT, ['cost' => $this->cost]);

        $key = hash(self::HASH_ALGORITHM, $this->salt);
        $aad = hash(self::HASH_ALGORITHM, hash('whirlpool', $this->salt));

        /**
         * Attempting to encrypt using AES256GCM
         */
        if (\Sodium\crypto_aead_aes256gcm_is_available()) {
            $nonce = substr($key, 0, \Sodium\CRYPTO_AEAD_AES256GCM_NPUBBYTES);
            $key = substr($key, 0, \Sodium\CRYPTO_AEAD_AES256GCM_KEYBYTES);
            $raw = \Sodium\crypto_aead_aes256gcm_encrypt(
                $raw,
                $aad,
                $nonce,
                $key
            );
        } else {
            $nonce = substr($key, 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
            $key = substr($key, 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
            $raw = \Sodium\crypto_aead_chacha20poly1305_encrypt(
                $raw,
                $aad,
                $nonce,
                $key
            );
        }

        $encrypted = base64_encode($raw);

        /**
         * Clear memory for variables
         */
        \Sodium\memzero($raw);
        \Sodium\memzero($key);
        \Sodium\memzero($nonce);
        \Sodium\memzero($aad);

        return $encrypted;
    }

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encrypted
     * @param string $raw A raw password
     * @param string $salt The salt
     * @return bool true if the password is valid, false otherwise
     * @throws \Exception
     */
    public function isPasswordValid($encrypted, $raw, $salt)
    {
        /**
         * Decode base64
         */
        $encrypted = base64_decode($encrypted);
        /**
         * Add salt to password
         */
        $raw = sprintf("pass_%s_%s", $raw, $salt);
        /**
         * Create sha512 hash - always have same length
         */
        $raw = hash(self::HASH_ALGORITHM, $raw);

        $key = hash(self::HASH_ALGORITHM, $this->salt);
        $aad = hash(self::HASH_ALGORITHM, hash('whirlpool', $this->salt));

        /**
         * Attempting to decrypt using AES256GCM
         */
        if (\Sodium\crypto_aead_aes256gcm_is_available()) {
            $nonce = substr($key, 0, \Sodium\CRYPTO_AEAD_AES256GCM_NPUBBYTES);
            $key = substr($key, 0, \Sodium\CRYPTO_AEAD_AES256GCM_KEYBYTES);
            $decrypted = \Sodium\crypto_aead_aes256gcm_decrypt(
                $encrypted,
                $aad,
                $nonce,
                $key
            );
        } else {
            $nonce = substr($key, 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
            $key = substr($key, 0, \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
            $decrypted = \Sodium\crypto_aead_chacha20poly1305_decrypt(
                $encrypted,
                $aad,
                $nonce,
                $key
            );
        }

        /**
         * Clear memory for variables
         */
        \Sodium\memzero($encrypted);
        \Sodium\memzero($key);
        \Sodium\memzero($nonce);
        \Sodium\memzero($aad);
        if ($decrypted === false) {
            /**
             * Clear memory for variables
             */
            \Sodium\memzero($raw);
            throw new BadCredentialsException("Bad ciphertext");
        }

        if(password_verify($raw, $decrypted) === false) {
            /**
             * Clear memory for variables
             */
            \Sodium\memzero($raw);
            \Sodium\memzero($decrypted);
            throw new BadCredentialsException("The presented password is invalid.");
        }

        /**
         * Clear memory for variables
         */
        \Sodium\memzero($raw);
        \Sodium\memzero($decrypted);

        return true;
    }
}
