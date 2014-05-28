<?php

require __DIR__.'/../vendor/rncryptor/rncryptor/autoload.php';

function decryptFile($file)
{

    if (!file_exists($file)){
        throw new \Exception("File  {$file} does not exist.");
    }

    $encryptedContents = file_get_contents($file);
    $encryptedContents = base64_decode($encryptedContents);
    $cryptor = new \RNCryptor\Decryptor();
    $contents = $cryptor->decrypt($encryptedContents, '123456');


    $newFile = __DIR__.'/decrypted.epub';
    file_put_contents($newFile, $contents);
}

decryptFile(__DIR__.'/encryptedByApp.epub');