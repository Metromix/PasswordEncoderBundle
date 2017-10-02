PasswordEncoderBundle
=====================
This Symfony-bundle add PHP Libsodium password encryption into your Symfony application.

## Installation

To install this package, add `metromix/password-encoder-bundle` to your composer.json:

```bash
$ php composer.phar require metromix/password-encoder-bundle
```
Now, [Composer][1] will automatically download all required files, and install them
for you.

### Step2: Enable the bundle

Enable the bundle in the kernel:

```php
<?php

// in AppKernel::registerBundles()
$bundles = [
    // ...
    new Metromix\PasswordEncoderBundle\MetromixPasswordEncoderBundle(),
    // ...
];
```

## Requirements

You need at least PHP 7.x with libsodium or PHP 7.2, mbstring is recommended but not required.

Congratulations! You're ready!


## Contributing

This is an open source project. If you're submitting a pull request, please follow the guidelines in the [Submitting a Patch][2] section.

[1]: https://getcomposer.org/doc/00-intro.md
[2]: https://contributing.readthedocs.org/en/latest/code/patches.html