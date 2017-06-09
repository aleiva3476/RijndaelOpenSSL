# RijndaelOpenSSL
 Rijndael algorithm for PHP and .NET
 
This class encrypt a string with password.

The result is compatible with the .NET implementation of the Rijndael algorithm.

Example of usage

```
include 'RijndaelOpenSSL.php';

$original = 'This is a text to encrypt!';
$pass ='ThisIsMyPassword';

$rijndael = new RijndaelOpenSSL();
$encriptado = $rijndael->encrypt($original, $pass);
$desencriptado = $rijndael->decrypt($encriptado, $pass);
```
