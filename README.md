HashPW
======
This is a Python program that prompts for a password and prints the
hash.  Also has a verify mode that confirms whether or not a provided
hash matches a typed password.

This command generates a wide variety of password hashes.  Sensible use
of exceptions handle most error conditions.

Run **`hashpw --help`** for info.

Supported algorithms (hash type identifiers `highlighted`):

  + bcrypt: Portable PHP password hashing framework, a.k.a. Phpass (`$P$`)
      - see http://www.mindrot.org/projects/py-bcrypt/
  + phpBB3 bcrypt (`$H$`)
  + [Blowfish](http://en.wikipedia.org/wiki/Crypt_(Unix)#Blowfish-based_scheme)
  + Unix schemes: Crypt (two character salt), MD5 (`$1$`), blowfish (`$2a$`), SHA-256 (`$5$`), SHA-512 (`$6$`)
  + Apache: SHA1 (`{SHA}`), MD5 (`$apr1$`)
  + MySql: SHA1 (`*`), Old
  + Basic MD5
  + SSHA
  + Django: PBKDF2

Bugs
----
  + When supplying a salt (not a full hash) in verify mode, get "ext-des
    hashing does not appear to be supported on this platform"

TO-DO
-----

  + Support Drupal 7's SHA-512-based secure hash (hash type identifier = "$S$")
  + Support generic [Password-Based Key Derivation Function 2](https://en.wikipedia.org/wiki/PBKDF2)
      - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
      - $pdkdf2$ (SHA-1)
      - $pdkdf2-sha256$ (SHA-256)
      - $pdkdf2-sha512$ (SHA-512)
  + Support scrypt <https://en.wikipedia.org/wiki/Scrypt>
  + Option to generate/recognise simple hashes (e.g. BasicMD5, OldPassword) with prefixes
  + Accept password on standard input (without confirmation)
  + Support "doveadm pw" encoding scheme suffixes (.b64, .base64 and .hex); see
    http://wiki2.dovecot.org/Authentication/PasswordSchemes
  + Support Argon2i password hashing algorithm: https://wiki.php.net/rfc/argon2_password_hash
