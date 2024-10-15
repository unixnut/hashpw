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
  + Unix schemes: Crypt (two character salt), Ext DES (`_`), MD5 (`$1$`), blowfish (`$2a$`, `$2y$`, `$2b$`), SHA-256 (`$5$`), SHA-512 (`$6$`)
  + Apache: SHA1 (`{SHA}`), MD5 (`$apr1$`)
  + MySql: SHA1 (`*`), MD5, Old
  + SSHA
  + HTTP basic authentication
  + Grub's PBKDF2 SHA512 (`grub.pbkdf2.sha512`)
  + Django: PBKDF2 (`pbkdf2_sha256`), PBKDF2 SHA1 (`pbkdf2_sha1`), Bcrypt SHA256 (`bcrypt_sha256`), Argon2 (`argon2`)
  + SCrypt (`$scrypt$`)
  + YesCrypt (`$y$`)

Bugs
----
  + When supplying a salt (not a full hash) in verify mode, get "ext-des
    hashing does not appear to be supported on this platform"

TO-DO
-----

  + Support Drupal 7's SHA-512-based secure hash (hash type identifier = `$S$`)
  + Support generic [Password-Based Key Derivation Function 2](https://en.wikipedia.org/wiki/PBKDF2)
      - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
      - `$pdkdf2$` (SHA-1)
      - `$pdkdf2-sha256$` (SHA-256)
      - `$pdkdf2-sha512$` (SHA-512)
  + Option to generate/recognise simple hashes (e.g. BasicMD5, OldPassword) with prefixes
  + Accept password on standard input (without confirmation)
  + Support "doveadm pw" encoding scheme suffixes (.b64, .base64 and .hex); see
    http://wiki2.dovecot.org/Authentication/PasswordSchemes
