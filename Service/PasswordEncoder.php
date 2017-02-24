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

use Metromix\PasswordEncoderBundle\Crypt\AES;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Class MixCryptSalted
 * @package Metromix\ForumBundle\Service
 */
class PasswordEncoder implements PasswordEncoderInterface
{
    /**
     * @var string
     */
    private $cost;
    /**
     * @var string
     */
    private $salt;

    /**
     * Constructor.
     *
     * @param int $cost The algorithmic cost that should be used
     * @param string $salt
     * @throws \RuntimeException         When no BCrypt encoder is available
     * @throws \InvalidArgumentException if cost is out of range
     */
    public function __construct($cost, $salt = null)
    {
        $cost = (int) $cost;
        if ($cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException('Cost must be in the range of 4-31.');
        }

        $this->cost = $cost;
        $this->salt = $salt;
    }

    /**
     * Encodes the raw password.
     *
     * It doesn't work with PHP versions lower than 5.3.7, since
     * the password compat library uses CRYPT_BLOWFISH hash type with
     * the "$2y$" salt prefix (which is not available in the early PHP versions).
     *
     * @see https://github.com/ircmaxell/password_compat/issues/10#issuecomment-11203833
     *
     * It is almost best to **not** pass a salt and let PHP generate one for you.
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
        $options = array('cost' => $this->cost);

        $var = sprintf("pass_%s_%s", $raw, $salt);
        $raw = hash('sha512', $var);
        if($this->salt !== null) {
            $raw = password_hash($raw, PASSWORD_BCRYPT, $options);
            $aes = new AES($raw, $this->salt, 256);

            return $aes->encrypt();
        }
        return password_hash($raw, PASSWORD_BCRYPT, $options);
    }

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encoded An encoded password
     * @param string $raw A raw password
     * @param string $salt The salt
     *
     * @return bool true if the password is valid, false otherwise
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        $var = sprintf("pass_%s_%s", $raw, $salt);
        $raw = hash('sha512', $var);
        if($this->salt !== null) {
            $aes = new AES($encoded, $this->salt, 256);

            $encoded = $aes->decrypt();
        }
        return password_verify($raw, $encoded);
    }
}