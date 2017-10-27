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
 * @name PasswordEncoderTest.php - 02-10-2017 10:49
 */
namespace Metromix\PasswordEncoderBundle\Tests;

use Metromix\PasswordEncoderBundle\Security\Encoder\PasswordEncoder;

class PasswordEncoderTest extends \PHPUnit_Framework_TestCase
{
    public function testLibsodiumEncode()
    {
        $this->assertTrue((extension_loaded("sodium") !== false || extension_loaded("libsodium") !== false));
        $globalSalt = hash('sha512', time());
        $plainPassword = uniqid();
        $plainSalt = hash('sha512', time()*time());
        $encoder = new PasswordEncoder($globalSalt);

        $encodedPassword = $encoder->encodePassword($plainPassword, $plainSalt);
        $decodedPassword = $encoder->isPasswordValid($encodedPassword, $plainPassword, $plainSalt);

        $this->assertTrue($decodedPassword);
    }
}
