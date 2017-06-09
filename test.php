<?php
include 'RijndaelOpenSSL.php';

$original = 'This is a text to encrypt!';
$pass ='ThisIsMyPassword';

$rijndael = new RijndaelOpenSSL();

$encriptado = $rijndael->encrypt($original, $pass);
$desencriptado = $rijndael->decrypt($encriptado, $pass);

echo 'Encriptado:' . PHP_EOL . $encriptado . PHP_EOL;
echo 'Desencriptado:' . PHP_EOL. $desencriptado . PHP_EOL;
