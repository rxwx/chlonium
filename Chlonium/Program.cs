using System;
using System.IO;

namespace Chlonium
{
    class Program
    {
        static void Main(string[] args)
        {
            string localStatePath = String.Empty;

            if (args.Length > 0)
            {

                localStatePath = args[0];
            }
            else
            {
                localStatePath = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", 
                    Environment.GetEnvironmentVariable("USERPROFILE"));
            }

            if (!File.Exists(localStatePath))
            {
                Console.WriteLine("[!] Local State file not found");
                return;
            }

            AesCrypto crypto = new AesCrypto(localStatePath);
            byte[] masterKey = crypto.GetEncryptionKey();
            Console.WriteLine("[+] Statekey = {0}", Convert.ToBase64String(masterKey));
        }
    }
}
