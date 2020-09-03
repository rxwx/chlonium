using System;
using PInvoke;
using System.IO;
using static PInvoke.BCrypt;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace Chlonium
{
    class AesCrypto
    {
        private string localStatePath;
        private byte[] key;

        public AesCrypto(string localStatePath)
        {
            this.localStatePath = localStatePath;
            InitDecryptor();
        }

        private void InitDecryptor()
        {
            this.key = GetEncryptionKey();
        }

        private static byte[] SubArray(byte[] data, int index, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        public byte[] GetEncryptionKey()
        {
            byte[] encryptedKey;
            string localState = File.ReadAllText(localStatePath);

            // Read encrypted Masterkey
            Regex r = new Regex("encrypted_key\":\"([a-z0-9+\\/=]+)\"", RegexOptions.IgnoreCase);

            if (!r.IsMatch(localState))
            {
                Console.WriteLine("[X] Couldn't find encrypted_key");
                return null;
            }

            encryptedKey = Convert.FromBase64String(r.Matches(localState)[0].Groups[1].Value);

            // Trim "DPAPI" prefix &
            // Decrypt masterkey with DPAPI
            return ProtectedData.Unprotect(
                SubArray(encryptedKey, 5, encryptedKey.Length - 5),
                null, DataProtectionScope.CurrentUser);
        }

        // Example taken with thanks from https://github.com/AArnott/pinvoke/issues/441
        public unsafe static byte[] GcmDecrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null)
        {

            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM))
            {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength
                || pbTag.Length > tagLengths.dwMaxLength
                || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                    throw new ArgumentException("Invalid tag length");

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
                {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData)
                    {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        //Initialize Cipher Text Byte Count
                        int pcbPlaintext = pbData.Length;

                        //Allocate Plaintext Buffer
                        byte[] pbPlaintext = new byte[pcbPlaintext];

                        fixed (byte* ciphertext = pbData)
                        fixed (byte* plaintext = pbPlaintext)
                        {
                            //Decrypt The Data
                            status = BCryptDecrypt(
                               key,
                               ciphertext,
                               pbData.Length,
                               &authInfo,
                               null,
                               0,
                               plaintext,
                               pbPlaintext.Length,
                               out pcbPlaintext,
                               0);
                        }
                        if (status == NTSTATUS.Code.STATUS_AUTH_TAG_MISMATCH)
                            throw new CryptographicException("BCryptDecrypt auth tag mismatch");
                        else if (status != NTSTATUS.Code.STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptDecrypt failed result {status:X} ");

                        return pbPlaintext;

                    }
                }
            }
        }


        public unsafe static byte[] GcmEncrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM))
            {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength
                || pbTag.Length > tagLengths.dwMaxLength
                || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                    throw new ArgumentException("Invalid tag length");

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
                {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData)
                    {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        //Initialize Cipher Text Byte Count
                        int pcbCipherText = pbData.Length;

                        //Allocate Cipher Text Buffer
                        byte[] pbCipherText = new byte[pcbCipherText];

                        fixed (byte* plainText = pbData)
                        fixed (byte* cipherText = pbCipherText)
                        {
                            //Encrypt The Data
                            status = BCryptEncrypt(
                               key,
                               plainText,
                               pbData.Length,
                               &authInfo,
                               null,
                               0,
                               cipherText,
                               pbCipherText.Length,
                               out pcbCipherText,
                               0);
                        }

                        if (status != NTSTATUS.Code.STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptEncrypt failed result {status:X} ");

                        return pbCipherText;

                    }
                }
            }
        }

        public byte[] Encrypt(byte[] plainText)
        {
            int NONCE_SIZE = 12;
            int PREFIX_SIZE = "v10".Length;
            int TAG_SIZE = 16;

            byte[] pbNonce = new byte[NONCE_SIZE]; // TODO: generate nonce
            byte[] pbData = plainText;
            byte[] pbTag = new byte[TAG_SIZE]; // generate tag

            byte[] encryptedBytes = GcmEncrypt(pbData, key, pbNonce, pbTag);
            return encryptedBytes; // TODO: add NONCE, TAG, and "v10" prefix
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            int NONCE_SIZE = 12;
            int PREFIX_SIZE = "v10".Length;
            int TAG_SIZE = 16;

            byte[] pbNonce = SubArray(cipherText, PREFIX_SIZE, NONCE_SIZE);
            byte[] pbData = SubArray(cipherText, PREFIX_SIZE + NONCE_SIZE, cipherText.Length - NONCE_SIZE - PREFIX_SIZE - TAG_SIZE);
            byte[] pbTag = SubArray(cipherText, PREFIX_SIZE + NONCE_SIZE + pbData.Length, TAG_SIZE);

            return GcmDecrypt(pbData, key, pbNonce, pbTag);
        }
    }
}
