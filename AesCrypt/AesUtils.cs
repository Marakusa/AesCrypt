using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesCrypt
{
    public static class AesUtils
    {
        private const int IV_LENGTH = 16;
        /// <summary>
        /// Cipher text using key provided
        /// </summary>
        /// <param name="text">The text to be ciphered.</param>
        /// <param name="key">the cipher key.</param>
        /// <returns>Base 64 ecnoded, Ciphered text</returns>
        public static string Encrypt(string text, string key)
        {
            if (text == null || text.Length <= 0)
                throw new ArgumentNullException(nameof(text));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            using (AesManaged myAes = new AesManaged())
            {
                byte[] encrypted;
                myAes.Key = Encoding.Default.GetBytes(key);
                //Generate random initialization vector
                var iv = GenerateIV();
                myAes.IV = iv;
                ICryptoTransform encryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
                //Initialization vector will be added in front of the ciphered text
                //Initialization vector is the first 16 bytes of ciphered text and then comes the text itself
                var ivAndEncrypted = new byte[iv.Length + encrypted.Length];
                iv.CopyTo(ivAndEncrypted, 0);
                encrypted.CopyTo(ivAndEncrypted, iv.Length);
                return Convert.ToBase64String(ivAndEncrypted);
            }
        }
        /// <summary>
        /// Deciphers Base64 encoded text
        /// </summary>
        /// <param name="encryptedWithIv">Base 64 encoded, Ciphered text with Iv in front of it.</param>
        /// <param name="key">The cipher key.</param>
        /// <returns>Plaintext</returns>
        public static string Decrypt(string encryptedWithIv, string key)
        {
            if (encryptedWithIv == null || encryptedWithIv.Length <= 0)
                throw new ArgumentNullException(nameof(encryptedWithIv));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(key);
            //Convert string to byte array
            byte[] encryptedArray = Convert.FromBase64String(encryptedWithIv);
            //Extract the Iv from the first 16 bytes of the array
            var Iv = GetIV(encryptedArray);
            //Extract the payload part without Iv
            var encrypted = new byte[encryptedArray.Length - IV_LENGTH];
            Array.Copy(encryptedArray, IV_LENGTH, encrypted, 0, encrypted.Length);
            string plainText;
            using (AesManaged myAes = new AesManaged())
            {
                myAes.IV = Iv;
                myAes.Key = Encoding.Default.GetBytes(key);
                ICryptoTransform decryptor = myAes.CreateDecryptor(myAes.Key, myAes.IV);
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plainText;
        }
        /// <summary>
        /// Generates the Initialization vector
        /// </summary>
        /// <returns>The initialization vector</returns>
        private static byte[] GenerateIV()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] nonce = new byte[IV_LENGTH];
                rng.GetBytes(nonce);
                return nonce;
            }
        }
        /// <summary>
        /// Extracts the initialization vector from the byte array
        /// </summary>
        /// <param name="arr">Byte array containing Iv and ciphertext</param>
        /// <returns>The initialization vector</returns>
        private static byte[] GetIV(byte[] arr)
        {
            byte[] IV = new byte[IV_LENGTH];
            Array.Copy(arr, 0, IV, 0, IV_LENGTH);
            return IV;
        }
    }
}
