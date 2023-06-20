using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using System.IO;
using System.Data.SQLite;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using Ookii.Dialogs.Wpf;
using SharpDPAPI;
using SharpChrome;
using static ChloniumUI.Browsers;
using static ChloniumUI.ExportMethods;
using static ChloniumUI.ImportMethods;
using System.Text.RegularExpressions;

namespace ChloniumUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    /// 

    public enum ImportMethod
    {
        DatabaseImport,
        StateKeyImport
    }

    public class ComboboxItem
    {
        public string Text { get; set; }
        public object Value { get; set; }

        public override string ToString()
        {
            return Text;
        }
    }

    public partial class MainWindow : Window
    {
        private string inputFile;

        private string dbType;

        private byte[] pvkBytes;

        private string password;

        private BrowserConfig browser = null;

        private string base64Key;

        private Type importerType;

        public MainWindow()
        {
            InitializeComponent();

            foreach (var browser in browserConfigs)
            {
                if (File.Exists(browser.CookieFile))
                {
                    ComboBox.Items.Add(browser);
                }
            }

            foreach (var typePair in ListImporters())
            {
                ComboBox_Importer.Items.Add(typePair);
            }
        }

        private bool IsHexKey(string value)
        {
            bool isHex;
            foreach (var c in value)
            {
                isHex = ((c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F'));

                if (!isHex)
                    return false;
            }
            return value.Length == 64;
        }

        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private bool ImportExportCheck()
        {
            if (string.IsNullOrEmpty(TextBox_File.Text) || !File.Exists(TextBox_File.Text))
            {
                MessageBox.Show("Enter a valid database file path", "Error");
                return false;
            }
            if (string.IsNullOrEmpty(StateKeyText.Text))
            {
                MessageBox.Show("Enter a valid state key", "Error");
                return false;
            }

            if (!IsStateKeyValid(StateKeyText.Text))
                return false;

            dbType = DetectDatabase();

            if (string.IsNullOrEmpty(dbType))
            {
                MessageBox.Show("Unknown database type", "Error");
                return false;
            }
            return true;
        }

        private byte[] GetStateKey(string value)
        {
            byte[] keyBytes;
            if (IsHexKey(value))
                keyBytes = StringToByteArray(value);
            else
                keyBytes = Convert.FromBase64String(value);
            return keyBytes;
        }

        private bool IsStateKeyValid(string value)
        {
            try
            {
                byte[] keyBytes = GetStateKey(value);

                if (keyBytes.Length == 32)
                {
                    return true;
                }
                else
                {
                    MessageBox.Show("State key is not the correct length", "Error");
                }
            }
            catch
            {
                MessageBox.Show("State key doesn't look right. Make sure it is base64 or hex encoded.", "Error");
            }
            return false;
        }

        private void StateKeyCheck_Click(object sender, RoutedEventArgs e)
        {
            if (IsStateKeyValid(StateKeyText.Text))
            {
                MessageBox.Show("State key looks good");
            }
        }

        private void Import_Click(object sender, RoutedEventArgs e)
        {
            if (!ImportExportCheck())
                return;

            if (browser == null)
            {
                MessageBox.Show("Please select a browser");
                return;
            }

            // kill chrome if it's running
            if (Process.GetProcessesByName(browser.ProcessName).Length > 0)
            {
                MessageBox.Show($"{browser.ProcessName} is running. Please close it first", "Error");
                return;
            }

            // initialize AES
            var crypto = new AesCrypto(browser.LocalState);

            string backupFile;

            List<Item> items = new List<Item>();

            byte[] keyBytes = GetStateKey(StateKeyText.Text);

            int count = 0;

            Importer importer = (Importer)Activator.CreateInstance(importerType, new object[] { browser, keyBytes });

            switch (dbType)
            {
                case "cookies":

                    // Backup Cookie file
                    backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.CookieFile), DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.CookieFile, backupFile, true);

                    if (importer.GetType() == typeof(DatabaseImporter))
                    {
                        items = ExportCookies(keyBytes, this.inputFile);

                        // re-encrypt all items
                        foreach (Cookie c in items)
                        {
                            c.encrypted_value = crypto.Encrypt(c.decrypted_value);
                        }
                        count = items.Count();
                        importer.ImportCookies(items);
                    }
                    else if (importer.GetType() == typeof(StateKeyImporter))
                    {
                        // Backup Local State file
                        backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.LocalState), DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                        File.Copy(browser.LocalState, backupFile, true);

                        // Copy new Cookie file
                        File.Copy(this.inputFile, browser.CookieFile, true);

                        importer.ImportCookies(null);
                        MessageBox.Show("Imported new State Key!");
                        return;
                    }

                    break;
                case "logins":

                    backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.LoginFile), DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.LoginFile, backupFile, true);

                    if (importer.GetType() == typeof(DatabaseImporter))
                    {
                        items = ExportLogins(keyBytes, this.inputFile);

                        // re-encrypt all items
                        foreach (Login i in items)
                        {
                            i.password_value = crypto.Encrypt(i.decrypted_password_value);
                        }
                        count = items.Count();
                        importer.ImportLogins(items);
                    }
                    else if (importer.GetType() == typeof(StateKeyImporter))
                    {
                        // Backup Local State file
                        backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.LocalState), DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                        File.Copy(browser.LocalState, backupFile, true);

                        // Copy new Login file
                        File.Copy(this.inputFile, browser.LoginFile, true);

                        importer.ImportLogins(null);
                        MessageBox.Show("Imported new State Key!");
                        return;
                    }

                    break;
                default:
                    return;
            }
            MessageBox.Show($"Imported {count} {dbType}!");
        }

        private void File_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                string filename = dlg.FileName;
                this.inputFile = filename;

                // Check file is sqlite3
                byte[] fileMagic = File.ReadAllBytes(this.inputFile).Take(15).ToArray();
                if (Encoding.UTF8.GetString(fileMagic) != "SQLite format 3")
                {
                    MessageBox.Show("Selected file is not a SQLite database", "Error");
                    this.inputFile = string.Empty;
                    return;
                }
                TextBox_File.Text = filename;
            }
        }

        public string DetectDatabase()
        {
            string dbType = string.Empty;
            string cs = string.Format("Data Source={0};", this.inputFile);
            var con = new SQLiteConnection(cs);
            con.Open();
            string stm = "SELECT name FROM sqlite_master WHERE type ='table' AND name = 'logins' OR name = 'cookies' LIMIT 1;";
            SQLiteCommand cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();
            if (reader.HasRows)
            {
                while (reader.Read())
                {
                    return (string)reader["name"];
                }
            }
            return dbType;
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            if (!ImportExportCheck())
                return;

            string outputFile = string.Empty;
            SaveFileDialog dlg = new SaveFileDialog
            {
                FileName = this.dbType,
                DefaultExt = ".txt",
                Filter = "Text File|*.txt"
            };

            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                outputFile = dlg.FileName;
            }

            // export cookies/logins to file

            List<Item> items;
            byte[] keyBytes = GetStateKey(StateKeyText.Text);

            switch (dbType)
            {
                case "cookies":
                    items = ExportCookies(keyBytes, this.inputFile);
                    break;
                case "logins":
                    items = ExportLogins(keyBytes, this.inputFile);
                    break;
                default:
                    return;
            }
            using (StreamWriter writer = File.CreateText(outputFile))
            {
                foreach (Item c in items)
                {
                    writer.WriteLine(c);
                }
            }

            if (items.Count >= 1)
                MessageBox.Show($"Exported {items.Count} {dbType}!");
        }

        private void ImportCookies(List<Item> items)
        {
            // SCARY STUFF!! Make sure we take a backup
            string cs = string.Format("Data Source={0};", browser.CookieFile);

            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();
            SQLiteCommand cmd = new SQLiteCommand("DELETE FROM cookies;", con);
            cmd.ExecuteNonQuery();

            cmd = con.CreateCommand();
            cmd.CommandText = string.Format("PRAGMA table_info(cookies);");
            var reader = cmd.ExecuteReader();
            bool hasTopFrameSiteKey = false;
            int nameIndex = reader.GetOrdinal("Name");
            while (reader.Read())
            {
                if (reader.GetString(nameIndex).Equals("top_frame_site_key"))
                {
                    hasTopFrameSiteKey = true;
                }
            }

            int exceptionsCount = 0;

            foreach (Cookie c in items)
            {
                if (hasTopFrameSiteKey)
                {
                    cmd = new SQLiteCommand("INSERT INTO cookies (creation_utc, top_frame_site_key, host_key, name, value, " +
                     "path, expires_utc, is_secure, is_httponly, last_access_utc, last_update_utc, has_expires, is_persistent, " +
                     "priority, encrypted_value, samesite, source_scheme, source_port, is_same_party) VALUES" +
                     " (@creation_utc, @top_frame_site_key, @host_key, @name, @value, @path, @expires_utc, @is_secure," +
                     "@is_httponly, @last_access_utc, @last_update_utc, @has_expires, @is_persistent, @priority, " +
                     "@encrypted_value, @samesite, @source_scheme, @source_port, @is_same_party)", con);
                    cmd.Parameters.AddWithValue("@top_frame_site_key", "");
                }
                else
                {
                    cmd = new SQLiteCommand("INSERT INTO cookies (creation_utc, host_key, name, value, " +
                     "path, expires_utc, is_secure, is_httponly, last_access_utc, last_update_utc, has_expires, is_persistent, " +
                     "priority, encrypted_value, samesite, source_scheme, source_port, is_same_party) VALUES" +
                     " (@creation_utc, @host_key, @name, @value, @path, @expires_utc, @is_secure," +
                     "@is_httponly, @last_access_utc, @last_update_utc, @has_expires, @is_persistent, @priority, " +
                     "@encrypted_value, @samesite, @source_scheme, @source_port, @is_same_party)", con);
                }

                cmd.Parameters.AddWithValue("@creation_utc", c.creation_utc);
                cmd.Parameters.AddWithValue("@host_key", c.host_key);
                cmd.Parameters.AddWithValue("@name", c.name);
                cmd.Parameters.AddWithValue("@value", c.value);
                cmd.Parameters.AddWithValue("@path", c.path);
                cmd.Parameters.AddWithValue("@expires_utc", c.expires_utc);
                cmd.Parameters.AddWithValue("@is_secure", c.is_secure);
                cmd.Parameters.AddWithValue("@is_httponly", c.is_httponly);
                cmd.Parameters.AddWithValue("@last_access_utc", c.last_access_utc);
                cmd.Parameters.AddWithValue("@last_update_utc", c.last_update_utc);
                cmd.Parameters.AddWithValue("@has_expires", c.has_expires);
                cmd.Parameters.AddWithValue("@is_persistent", c.is_persistent);
                cmd.Parameters.AddWithValue("@priority", c.priority);
                cmd.Parameters.AddWithValue("@encrypted_value", c.encrypted_value);
                cmd.Parameters.AddWithValue("@samesite", c.samesite);
                cmd.Parameters.AddWithValue("@source_scheme", c.source_scheme);
                cmd.Parameters.AddWithValue("@source_port", c.source_port);
                cmd.Parameters.AddWithValue("@is_same_party", c.is_same_party);

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    if (exceptionsCount < 3)
                    {
                        MessageBox.Show(ex.Message);
                        exceptionsCount++;
                    }
                }
            }
        }

        private void ComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            this.browser = (BrowserConfig)ComboBox.SelectedItem;
        }

        private bool ValidatePasswordOrPvk(string value, bool quiet = false)
        {
            this.pvkBytes = null;
            this.password = string.Empty;

            if (File.Exists(value))
            {
                byte[] content = File.ReadAllBytes(value);
                if (BitConverter.ToUInt32(content, 0) != 0xb0b5f11e)
                {
                    MessageBox.Show("Selected file does not appear to be a valid backup key");
                    return false;
                }
                else
                {
                    if (!quiet)
                        MessageBox.Show($"Using domain backup key file (seems valid)");
                    this.pvkBytes = content;
                    return true;
                }
            }
            else
            {
                // coud be a password or base64 pvk
                // 256 is max password size, but pvk will always be bigger
                if (PasswordOrPVK.Text.Length <= 256 && PasswordOrPVK.Text.Length > 0)
                {
                    if (!quiet)
                        MessageBox.Show(string.Format("Will assume data provided is {0}",
                            Regex.IsMatch(PasswordOrPVK.Text, @"^([a-f0-9]{32}|[a-f0-9]{40})$", RegexOptions.IgnoreCase)
                            ? "a hash" : "a password"));
                    this.password = PasswordOrPVK.Text;
                    return true;
                }
                else
                {
                    // could still be a base64 pvk, lets validate
                    try
                    {
                        byte[] content = Convert.FromBase64String(PasswordOrPVK.Text);
                        if (BitConverter.ToUInt32(content, 0) != 0xb0b5f11e)
                        {
                            MessageBox.Show("Base64 backup key provided, but is not valid");
                            return false;
                        }
                        else
                        {
                            if (!quiet)
                                MessageBox.Show($"Using base64 domain backup key (seems valid)");
                            this.pvkBytes = content;
                            return true;
                        }
                    }
                    catch { }
                    MessageBox.Show("Password or Backup Key is invalid");
                    return false;
                }
            }
        }

        private void PasswordOrPVK_Check(object sender, RoutedEventArgs e)
        {
            ValidatePasswordOrPvk(PasswordOrPVK.Text);
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidatePasswordOrPvk(PasswordOrPVK.Text, true))
                return;

            if (!ValidateStateFile(TextBox_LocalState.Text))
                return;

            if (!ValidateMasterKeyDirectory(TextBox_Masterkey.Text))
                return;

            // First decrypt the DPAPI masterkey
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();
            if (pvkBytes != null && pvkBytes.Length > 0)
            {
                masterkeys = Triage.TriageUserMasterKeys(pvkBytes, false, "", "", TextBox_Masterkey.Text);
            }
            else if (!string.IsNullOrEmpty(password))
            {
                masterkeys = TriageExtension.TriageUserMasterKeys(password, TextBox_Masterkey.Text);
            }

            if (masterkeys.Count == 0)
            {
                MessageBox.Show("Failed to decrypt DPAPI MasterKey(s)");
                return;
            }

            byte[] decryptedKey = Chrome.DecryptBase64StateKey(masterkeys, this.base64Key, false);

            if (decryptedKey == null || decryptedKey.Length == 0)
            {
                MessageBox.Show(string.Format("Failed to decrypt State Key with supplied {0}", this.pvkBytes != null ? "backup key" : "password"));
            }
            else if (Encoding.UTF8.GetString(decryptedKey).ToLower().Contains("masterkey needed"))
            {
                MessageBox.Show(string.Format("Failed: {0}", Encoding.UTF8.GetString(decryptedKey)));
            }
            else
            {
                string base64StateKey = Convert.ToBase64String(decryptedKey);
                Clipboard.SetText(base64StateKey);
                StateKeyText.Text = base64StateKey;
                MessageBox.Show("Success! State key copied to clipboard");
            }
        }

        private void PasswordOrPVK_Browse(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                if (ValidatePasswordOrPvk(dlg.FileName, true))
                    PasswordOrPVK.Text = dlg.FileName;
            }
        }

        private bool ValidateMasterKeyDirectory(string folderName)
        {
            int keys = 0;
            if ((File.GetAttributes(folderName) & FileAttributes.Directory) == FileAttributes.Directory)
            {
                foreach (var file in Directory.GetFiles(folderName))
                {
                    try
                    {
                        FileInfo f = new FileInfo(file);
                        if (Helpers.IsGuid(f.Name))
                        {
                            var masterKeyBytes = File.ReadAllBytes(file);
                            if (Helpers.IsGuid(Encoding.Unicode.GetString(masterKeyBytes, 12, 72)))
                                keys++;
                        }
                    }
                    catch { }
                }
            }
            return keys > 0;
        }

        private void DPAPIMasterKey_Browse(object sender, RoutedEventArgs e)
        {
            VistaFolderBrowserDialog dlg = new VistaFolderBrowserDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                if (ValidateMasterKeyDirectory(dlg.SelectedPath))
                    TextBox_Masterkey.Text = dlg.SelectedPath;
                else
                    MessageBox.Show("Selected directory does not contain any DPAPI masterkeys");
            }
        }

        private bool ValidateStateFile(string filename)
        {
            try
            {
                string json = File.ReadAllText(filename);
                JObject state = JObject.Parse(json);
                this.base64Key = state["os_crypt"]["encrypted_key"].ToString();
                return true;
            }
            catch
            {
                MessageBox.Show("Local State file is invalid");
                return false;
            }
        }

        private void LocalState_Browse(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                if (ValidateStateFile(dlg.FileName))
                    TextBox_LocalState.Text = dlg.FileName;
            }
        }

        private void ComboBox_Importer_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            this.importerType = ((KeyValuePair<Type, string>)ComboBox_Importer.SelectedItem).Key;
        }
    }
}
