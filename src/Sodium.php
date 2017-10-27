<?php
declare(strict_types = 1);
/*
 * This file is part of the BrandOriented package.
 *
 * (c) Metromix.pl
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author Dominik Labudzinski <dominik@labudzinski.com>
 * @name Sodium.php - 27-10-2017 11:34
 */

namespace Metromix\PasswordEncoderBundle;


/**
 * Class Sodium
 * @package BrandOriented
 */
class Sodium
{
    public const CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;
    public const CRYPTO_AEAD_AES256GCM_NSECBYTES = 0;
    public const CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;
    public const CRYPTO_AEAD_AES256GCM_ABYTES = 16;
    public const CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
    public const CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = 0;
    public const CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
    public const CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
    public const CRYPTO_AUTH_BYTES = 32;
    public const CRYPTO_AUTH_KEYBYTES = 32;
    public const CRYPTO_BOX_SEALBYTES = 16;
    public const CRYPTO_BOX_SECRETKEYBYTES = 32;
    public const CRYPTO_BOX_PUBLICKEYBYTES = 32;
    public const CRYPTO_BOX_KEYPAIRBYTES = 64;
    public const CRYPTO_BOX_MACBYTES = 16;
    public const CRYPTO_BOX_NONCEBYTES = 24;
    public const CRYPTO_BOX_SEEDBYTES = 32;
    public const CRYPTO_KX_BYTES = 32;
    public const CRYPTO_KX_PUBLICKEYBYTES = 32;
    public const CRYPTO_KX_SECRETKEYBYTES = 32;
    public const CRYPTO_GENERICHASH_BYTES = 32;
    public const CRYPTO_GENERICHASH_BYTES_MIN = 16;
    public const CRYPTO_GENERICHASH_BYTES_MAX = 64;
    public const CRYPTO_GENERICHASH_KEYBYTES = 32;
    public const CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
    public const CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX = '$7$';
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 534288;
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432;
    public const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824;
    public const CRYPTO_SCALARMULT_BYTES = 32;
    public const CRYPTO_SCALARMULT_SCALARBYTES = 32;
    public const CRYPTO_SHORTHASH_BYTES = 8;
    public const CRYPTO_SHORTHASH_KEYBYTES = 16;
    public const CRYPTO_SECRETBOX_KEYBYTES = 32;
    public const CRYPTO_SECRETBOX_MACBYTES = 16;
    public const CRYPTO_SECRETBOX_NONCEBYTES = 24;
    public const CRYPTO_SIGN_BYTES = 64;
    public const CRYPTO_SIGN_SEEDBYTES = 32;
    public const CRYPTO_SIGN_PUBLICKEYBYTES = 32;
    public const CRYPTO_SIGN_SECRETKEYBYTES = 64;
    public const CRYPTO_SIGN_KEYPAIRBYTES = 96;
    public const CRYPTO_STREAM_KEYBYTES = 32;
    public const CRYPTO_STREAM_NONCEBYTES = 24;
    public const CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 4;
    public const CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 33554432;
    public const CRYPTO_PWHASH_OPSLIMIT_MODERATE = 6;
    public const CRYPTO_PWHASH_MEMLIMIT_MODERATE = 134217728;
    public const CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 8;
    public const CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 536870912;
    
    /**
     * Get a formatted password hash (for storage)
     * Argon2i
     *
     * @param string $passwd
     * @param int $opslimit
     * @param int $memlimit
     * @return string $string
     * @throws \Exception
     */
    public static function crypto_pwhash_str(
        string $passwd,
        int $opslimit,
        int $memlimit
    ): string {
        if(extension_loaded("sodium")) {
            return sodium_crypto_pwhash_str($passwd, $opslimit, $memlimit);
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_pwhash_str($passwd, $opslimit, $memlimit);
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Can you access AES-256-GCM? This is only available if you have supported
     * hardware.
     * @return bool
     * @throws \Exception
     */
    public static function crypto_aead_aes256gcm_is_available(): bool
    {
        if(extension_loaded("sodium")) {
            return sodium_crypto_aead_aes256gcm_is_available();
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_aead_aes256gcm_is_available();
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Authenticated Encryption with Associated Data (encrypt)
     * ChaCha20 + Poly1305
     *
     * @param string $msg plaintext message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     * @throws \Exception
     */
    public static function crypto_aead_chacha20poly1305_encrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        if(extension_loaded("sodium")) {
            return sodium_crypto_aead_chacha20poly1305_encrypt(
                $msg,
                $nonce,
                $key,
                $ad
            );
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_aead_chacha20poly1305_encrypt(
                $msg,
                $nonce,
                $key,
                $ad
            );
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Wipe a buffer
     *
     * @param &string $nonce
     */
    public static function memzero(
        string &$target
    ) {
        if(extension_loaded("sodium")) {
            sodium_memzero($target);
        } else if(extension_loaded("libsodium")) {
            \Sodium\memzero($target);
        }
    }

    /**
     * Authenticated Encryption with Associated Data (decrypt)
     * ChaCha20 + Poly1305
     *
     * @param string $msg encrypted message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     * @throws \Exception
     */
    public static function crypto_aead_chacha20poly1305_decrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        if(extension_loaded("sodium")) {
            return sodium_crypto_aead_chacha20poly1305_decrypt($msg, $nonce, $key, $ad);
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_aead_chacha20poly1305_decrypt($msg, $nonce, $key, $ad);
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Verify a password against a hash
     * Argon2i
     *
     * @param string $hash
     * @param string $passwd
     * @return bool
     * @throws \Exception
     */
    public static function crypto_pwhash_str_verify(
        string $hash,
        string $passwd
    ): bool {
        if(extension_loaded("sodium")) {
            return sodium_crypto_pwhash_str_verify($hash, $passwd);
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_pwhash_str_verify($hash, $passwd);
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Authenticated Encryption with Associated Data (encrypt)
     * AES-256-GCM
     *
     * @param string $msg plaintext message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     * @throws \Exception
     */
    public static function crypto_aead_aes256gcm_encrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        if(extension_loaded("sodium")) {
            return sodium_crypto_aead_aes256gcm_encrypt($msg, $nonce, $key, $ad);
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_aead_aes256gcm_encrypt($msg, $nonce, $key, $ad);
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }

    /**
     * Authenticated Encryption with Associated Data (decrypt)
     * AES-256-GCM
     *
     * @param string $msg encrypted message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     * @throws \Exception
     */
    public static function crypto_aead_aes256gcm_decrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        if(extension_loaded("sodium")) {
            return sodium_crypto_aead_aes256gcm_decrypt($msg, $nonce, $key, $ad);
        } else if(extension_loaded("libsodium")) {
            return \Sodium\crypto_aead_aes256gcm_decrypt($msg, $nonce, $key, $ad);
        }

        throw new \Exception('Sodium doesn\'t exist.');
    }
}