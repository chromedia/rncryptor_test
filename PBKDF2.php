<?php
/**
 * Based on
 * Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm).
 * Copyright (c) 2013, Taylor Hornby
 * All rights reserved.
 *
 * TODO: copyright notice
 *
 * @author Harold Modesto <harold.modesto@chromedia.com>
 *
 */
class PBKDF2
{
    // These constants may be changed without breaking existing hashes.
    const PBKDF2_HASH_ALGORITHM = "sha256";
    const PBKDF2_ITERATIONS = 1000;
    const PBKDF2_SALT_BYTES = 24;
    const PBKDF2_HASH_BYTES = 24;

    const HASH_SECTIONS = 4;
    const HASH_ALGORITHM_INDEX = 0;
    const HASH_ITERATION_INDEX = 1;
    const HASH_SALT_INDEX = 2;
    const HASH_PBKDF2_INDEX = 3;

    /**
     * Creates a hash for the given password
     *
     * @param string $password    the password to hash
     * @return string             the hashed password in format "algorithm:iterations:salt:hash"
     */
    public function createHash($password)
    {
        $salt = base64_encode(mcrypt_create_iv( PBKDF2::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM ));

        return PBKDF2::PBKDF2_HASH_ALGORITHM . ":" . PBKDF2::PBKDF2_ITERATIONS . ":" .  $salt . ":" .
                        base64_encode($this->hash(
                            PBKDF2::PBKDF2_HASH_ALGORITHM,
                            $password,
                            $salt,
                            PBKDF2::PBKDF2_ITERATIONS,
                            PBKDF2::PBKDF2_HASH_BYTES,
                            true
        ));
    }

    /**
     * Checks if the given password matches the given hash created by PBKDF::create_hash( string )
     *
     * @param string $password     the password to check
     * @param string $goodHash     the hash which should be match the password
     * @return boolean             true if $password and $goodHash match, false otherwise
     *
     * @see PBKDF2::createHash
     */
    public function validatePassword($password, $goodHash)
    {
        $params = explode( ":", $goodHash );
        if( count( $params ) < HASH_SECTIONS )
            return false;
        $pbkdf2 = base64_decode( $params[ PBKDF2::HASH_PBKDF2_INDEX ] );
        return $this->slowEquals(
                        $pbkdf2,
                        $this->hash(
                                        $params[ PBKDF2::HASH_ALGORITHM_INDEX ],
                                        $password,
                                        $params[ PBKDF2::HASH_SALT_INDEX ],
                                        (int)$params[ PBKDF2::HASH_ITERATION_INDEX ],
                                        strlen( $pbkdf2 ),
                                        true
                        )
        );
    }

    /**
     * Compares two strings $a and $b in length-constant time
     *
     * @param string $a    the first string
     * @param string $b    the second string
     * @return boolean     true if they are equal, false otherwise
     */
    public function slowEquals( $a, $b )
    {
        $diff = strlen( $a ) ^ strlen( $b );
        for( $i = 0; $i < strlen( $a ) && $i < strlen( $b ); $i++ )
        {
            $diff |= ord( $a[ $i ] ) ^ ord( $b[ $i ] );
        }
        return $diff === 0;
    }

    /**
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     * Added support for the native PHP implementation by TheBlintOne
     *
     * @param string $algorithm                                 the hash algorithm to use. Recommended: SHA256
     * @param string $password                                  the Password
     * @param string $salt                                      a salt that is unique to the password
     * @param int $count                                        iteration count. Higher is better, but slower. Recommended: At least 1000
     * @param int $keyLength                                   the length of the derived key in bytes
     * @param boolean $rawOutput [optional] (default false)    if true, the key is returned in raw binary format. Hex encoded otherwise
     * @return string                                           a $keyLength-byte key derived from the password and salt,
     *                                                          depending on $rawOutput this is either Hex encoded or raw binary
     * @throws Exception                                        if the hash algorithm are not found or if there are invalid parameters
     */
    public function hash($algorithm, $password, $salt, $count, $keyLength, $rawOutput = false )
    {
        $algorithm = strtolower( $algorithm );
        if( !in_array( $algorithm, hash_algos() , true ) )
            throw new Exception( 'PBKDF2 ERROR: Invalid hash algorithm.' );
        if( $count <= 0 || $keyLength <= 0 )
            throw new Exception( 'PBKDF2 ERROR: Invalid parameters.' );

        // use the native implementation of the algorithm if available
        if( function_exists( "hash_pbkdf2" ) )
        {
            return hash_pbkdf2( $algorithm, $password, $salt, $count, $keyLength, $rawOutput );
        }

        $hashLength = strlen( hash( $algorithm, "", true ) );
        $blockCount = ceil( $keyLength / $hashLength );

        $output = "";
        for( $i = 1; $i <= $blockCount; $i++ )
        {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack( "N", $i );
            // first iteration
            $last = $xorsum = hash_hmac( $algorithm, $last, $password, true );
            // perform the other $count - 1 iterations
            for( $j = 1; $j < $count; $j++ )
            {
                $xorsum ^= ( $last = hash_hmac( $algorithm, $last, $password, true ) );
            }
            $output .= $xorsum;
        }

        if ($rawOutput) {
            return substr( $output, 0, $keyLength );
        } else {
            return bin2hex(substr($output, 0, $keyLength ));
        }
    }
}


/**

-(BOOL) decryptEpubWithPath:(NSString *) bookPath {

    NSLog(@"%@",bookPath);

    NSString *path = [NSString stringWithFormat:@"%@",[NSHomeDirectory() stringByAppendingPathComponent:kTempReaderFilesFolder]];

    // create Directory if req'd
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
    }

    NSData *encryptedData = [NSData dataWithContentsOfFile:bookPath];

    NSError *error;

    NSData *decryptedData = [RNDecryptor decryptData:encryptedData
    withPassword:@"aPassword"
    error:&error];

    NSLog(@"decryptedData.length %i", decryptedData.length);

    NSString *unzipPath = [NSString stringWithFormat:@"/Library/Caches/TempBooks/%@",[bookPath lastPathComponent]];
    NSString *unzipAbsolutePath = [NSHomeDirectory() stringByAppendingFormat:@"%@",unzipPath];

    NSLog(@"unzipPath %@", unzipAbsolutePath);

    NSError *fileWriteError;

    if (decryptedData) {
        [decryptedData writeToFile:unzipAbsolutePath options:NSDataWritingAtomic error:&fileWriteError];
    }

    NSData *dataAtEncryptedFilePath = [NSData dataWithContentsOfFile:unzipAbsolutePath];

    NSLog(@"dataAtEncryptedFilePath.length %i", dataAtEncryptedFilePath.length);

    if (dataAtEncryptedFilePath) {
        return YES;
    }
    else {
        return NO;
    }
}
*/