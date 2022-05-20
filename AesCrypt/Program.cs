using System;

namespace AesCrypt
{
    public class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] != "e" && args[0] != "d")
            {
                Console.WriteLine("Please give a parameter (e: encrypt, d: decrypt)");
                return;
            }

            if (args.Length == 1)
            {
                Console.WriteLine("Please give a value to crypt");
                return;
            }

            if (args.Length == 2)
            {
                Console.WriteLine("Please give a crypt key");
                return;
            }

            switch (args[0])
            {
                case "e":
                    Console.WriteLine($"Encrypted value:\n{AesUtils.Encrypt(args[1], args[2])}");
                    break;
                case "d":
                    Console.WriteLine($"Decrypted value:\n{AesUtils.Decrypt(args[1], args[2])}");
                    break;
                default:
                    Console.WriteLine($"Invalid crypt action: {args[0]}");
                    break;
            }
        }
    }
}
