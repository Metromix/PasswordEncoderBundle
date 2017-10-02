<?php
/*
 * This file is part of the BrandOriented package.
 *
 * (c) Metromix.pl
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author Dominik Labudzinski <dominik@labudzinski.com>
 * @name PasswordEncoder.php - 13-12-2016 11:23
 */

namespace Metromix\PasswordEncoderBundle\Service;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class PasswordEncoder
 * @package Metromix\ForumBundle\Service
 */
class PasswordEncoder implements PasswordEncoderInterface
{
    const HASH_ALGORITHM = 'sha512';
    /**
     * @var string
     */
    private $salt;

    /**
     * Constructor.
     *
     * @param string $salt
     * @throws \RuntimeException         When no BCrypt encoder is available
     * @throws \InvalidArgumentException if cost is out of range
     */
    public function __construct($salt = null)
    {
        if($salt === null) {
            throw new \InvalidArgumentException('Salt can not be empty.');
        }
        $this->salt = $salt;
        if(function_exists('\Sodium\library_version_major') !== true) {
            throw new \InvalidArgumentException('Libsodium doesn\'t exist.');
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
        $raw = sprintf("pass_%s_%s", $raw, $salt);
        $raw = \Sodium\crypto_pwhash_str(
            $raw,
            \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );

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
        $raw = sprintf("pass_%s_%s", $raw, $salt);
        $key = hash(self::HASH_ALGORITHM, $this->salt);
        $aad = hash(self::HASH_ALGORITHM, hash('whirlpool', $this->salt));

        $encrypted = base64_decode($encrypted);

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
            \Sodium\memzero($decrypted);
            throw new \Exception("Bad ciphertext");
        }

        if (\Sodium\crypto_pwhash_str_verify($decrypted, $raw)) {
            /**
             * Clear memory for variables
             */
            \Sodium\memzero($raw);
            \Sodium\memzero($decrypted);
            return true;
        }

        /**
         * Clear memory for variables
         */
        \Sodium\memzero($raw);
        \Sodium\memzero($decrypted);
        return false;
    }
}
