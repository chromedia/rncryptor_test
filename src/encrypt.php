<?php

require __DIR__.'/../vendor/rncryptor/rncryptor/autoload.php';


/**
 *
 * @param string $file
 * @throws \Exception
 * @return string path to file
 */
function encryptFile($file)
{
    if (!file_exists($file)){
    	throw new \Exception("File  {$file} does not exist.");
    }

    $contents = file_get_contents($file);
    $cryptor = new  \RNCryptor\Encryptor();

    // TODO: get this from a config and choose a more secure password
    $password = '123456';

    // TODO: verify settings to match with iOS code, we may have to generate our custom hmac and iv
    $encryptedContents = $cryptor->encrypt($contents, $password);


    $baseName = basename($file);
    $parts = pathinfo($file);
    // set this to where ever you want to store the file
    $targetDirectory = __DIR__;
    $fileName = $parts['filename'].'-encrypted.'.$parts['extension'];

    // write encrypted file
    $encryptedFile = realpath($targetDirectory.DIRECTORY_SEPARATOR.$fileName);
    file_put_contents($encryptedFile, $encryptedContents);


    return $encryptedFile;
}

encryptFile(__DIR__.'/gutenberg30017.epub');