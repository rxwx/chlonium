using SharpDPAPI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Windows;

namespace ChloniumUI
{
    static class TriageExtension
    {
        public static string GetSidFromBKFile(string bkFile)
        {
            string sid = string.Empty;
            byte[] bkBytes = File.ReadAllBytes(bkFile);

            if (bkBytes.Length > 28)
            {
                try
                {
                    SecurityIdentifier sidObj = new SecurityIdentifier(bkBytes, 0x3c);
                    sid = sidObj.Value;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to parse BK file: {ex.Message}");
                }
            }
            return sid;
        }

        public static Dictionary<string, string> TriageUserMasterKeys(string password, string target)
        {
            // Extension to SharpDPAPI TriageMasterKeys method to support specifying a target and password

            Dictionary<string, string> mappings = new Dictionary<string, string>();
            string sid = string.Empty;

            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(target) || !Directory.Exists(target))
                return mappings;

            // First check if there is a BK file we can get the SID from
            foreach (string file in Directory.GetFiles(target, "*", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(file).StartsWith("BK-"))
                {
                    sid = GetSidFromBKFile(file);
                    if (!string.IsNullOrEmpty(sid))
                        break;
                }
            }

            // Fall back to directory name
            if (string.IsNullOrEmpty(sid) && Regex.IsMatch(Path.GetFileName(target), @"^S-\d-\d+-(\d+-){1,14}\d+$", RegexOptions.IgnoreCase))
            {
                sid = Path.GetFileName(target);
            }
            else if (string.IsNullOrEmpty(sid))
            {
                MessageBox.Show("Could not determine users's SID. " + 
                    "Ensure that DPAPI Masterkey directory name contains the user SID, " +
                    "OR that the BK-<NETBIOSDOMAINNAME> file is present");
                return mappings;
            }

            byte[] hmacBytes = Dpapi.CalculateKeys(password, sid, true);

            foreach (string file in Directory.GetFiles(target, "*", SearchOption.AllDirectories))
            {
                if (!Regex.IsMatch(file, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                    continue;

                byte[] masterKeyBytes = File.ReadAllBytes(file);
                try
                {
                    KeyValuePair<string, string> plaintextMasterKey = new KeyValuePair<string, string>();

                    if (!string.IsNullOrEmpty(password))
                    {
                        plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masterKeyBytes, hmacBytes);
                    }
                    mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                }
                catch (Exception e)
                {
                    MessageBox.Show($"Error triaging {file} : {e.Message}");
                }
            }
            return mappings;
        }
    }
}
