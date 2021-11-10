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
using SharpDPAPI;
using SharpChrome;
using static ChloniumUI.Browsers;
using Ookii.Dialogs.Wpf;

namespace ChloniumUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string inputFile;

        private string dbType;

        private byte[] pvkBytes;

        private string password;

        private BrowserConfig browser = null;

        private string base64Key;

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
            if (String.IsNullOrEmpty(TextBox_File.Text) || !File.Exists(TextBox_File.Text))
            {
                MessageBox.Show("Enter a valid database file path", "Error");
                return false;
            }
            if (String.IsNullOrEmpty(StateKeyText.Text))
            {
                MessageBox.Show("Enter a valid state key", "Error");
                return false;
            }

            if (!IsStateKeyValid(StateKeyText.Text))
                return false;

            dbType = DetectDatabase();

            if (String.IsNullOrEmpty(dbType))
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
            int count = 0;

            switch (dbType)
            {
                case "cookies":
                    backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.CookieFile),
                        DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.CookieFile, backupFile, true);
                    items = ExportCookies();

                    // re-encrypt all items
                    foreach (Cookie c in items)
                    {
                        c.encrypted_value = crypto.Encrypt(c.decrypted_value);
                    }
                    count = items.Count();
                    ImportCookies(items);
                    break;
                case "logins":
                    backupFile = string.Format("{0}_{1}.bak", Path.GetFileName(browser.LoginFile),
                        DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.LoginFile, backupFile, true);

                    items = ExportLogins();

                    // re-encrypt all items
                    foreach (Login i in items)
                    {
                        i.password_value = crypto.Encrypt(i.decrypted_password_value);
                    }
                    count = items.Count();
                    ImportLogins(items);
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

            switch (dbType)
            {
                case "cookies":
                    items = ExportCookies();
                    break;
                case "logins":
                    items = ExportLogins();
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

<<<<<<< HEAD
            cmd = con.CreateCommand();
            cmd.CommandText = string.Format("PRAGMA table_info(cookies);");
            SQLiteDataReader reader = cmd.ExecuteReader();
            bool hasTopFrameSiteKey = false;
            int nameIndex = reader.GetOrdinal("Name");
            while (reader.Read())
            {
                if (reader.GetString(nameIndex).Equals("top_frame_site_key"))
                {
                    hasTopFrameSiteKey = true;
                }
            }

=======
>>>>>>> parent of 75ca963 (Add support for top_frame_site_key)
            int exceptionsCount = 0;

            foreach (Cookie c in items)
            {
                cmd = new SQLiteCommand("INSERT INTO cookies (creation_utc, host_key, name, value, " +
                    "path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, " +
                    "priority, encrypted_value, samesite, source_scheme) VALUES" +
                    " (@creation_utc, @host_key, @name, @value, @path, @expires_utc, @is_secure," +
                    "@is_httponly, @last_access_utc, @has_expires, @is_persistent, @priority, " +
                    "@encrypted_value, @samesite, @source_scheme)", con);
                cmd.Parameters.AddWithValue("@creation_utc", c.creation_utc);
                cmd.Parameters.AddWithValue("@host_key", c.host_key);
                cmd.Parameters.AddWithValue("@name", c.name);
                cmd.Parameters.AddWithValue("@value", c.value);
                cmd.Parameters.AddWithValue("@path", c.path);
                cmd.Parameters.AddWithValue("@expires_utc", c.expires_utc);
                cmd.Parameters.AddWithValue("@is_secure", c.is_secure);
                cmd.Parameters.AddWithValue("@is_httponly", c.is_httponly);
                cmd.Parameters.AddWithValue("@last_access_utc", c.last_access_utc);
                cmd.Parameters.AddWithValue("@has_expires", c.has_expires);
                cmd.Parameters.AddWithValue("@is_persistent", c.is_persistent);
                cmd.Parameters.AddWithValue("@priority", c.priority);
                cmd.Parameters.AddWithValue("@encrypted_value", c.encrypted_value);
                cmd.Parameters.AddWithValue("@samesite", c.samesite);
                cmd.Parameters.AddWithValue("@source_scheme", c.source_scheme);

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

        private void ImportLogins(List<Item> items)
        {
            // SCARY STUFF!! Make sure we take a backup
            string cs = string.Format("Data Source={0};", browser.LoginFile);

            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();
            SQLiteCommand cmd = new SQLiteCommand("DELETE FROM logins;", con);
            cmd.ExecuteNonQuery();

            cmd = con.CreateCommand();
            cmd.CommandText = string.Format("PRAGMA table_info(logins);");
            SQLiteDataReader reader = cmd.ExecuteReader();
            bool hasPreferred = false;
            int nameIndex = reader.GetOrdinal("Name");
            while (reader.Read())
            {
                if (reader.GetString(nameIndex).Equals("preferred"))
                {
                    hasPreferred = true;
                }
            }

            int exceptionsCount = 0;

            foreach (Login c in items)
            {
                string sqlCmd;

                if (hasPreferred)
                {
                    sqlCmd = "INSERT INTO logins (origin_url, action_url, username_element, username_value, " +
                    "password_element, password_value, submit_element, signon_realm, preferred, date_created, blacklisted_by_user, " +
                    "scheme, password_type, times_used, form_data, date_synced, display_name, icon_url, federation_url, skip_zero_click, " +
                    "generation_upload_status, possible_username_pairs, id, date_last_used, moving_blocked_for) VALUES" +
                    " (@origin_url, @action_url, @username_element, @username_value, @password_element, @password_value, @submit_element," +
                    "@signon_realm, @preferred, @date_created, @blacklisted_by_user, @scheme, " +
                    "@password_type, @times_used, @form_data, @date_synced, @display_name, @icon_url, @federation_url, " +
                    "@skip_zero_click, @generation_upload_status, @possible_username_pairs, @id, @date_last_used, @moving_blocked_for)";
                    cmd = new SQLiteCommand(sqlCmd, con);
                    cmd.Parameters.AddWithValue("@preferred", c.preferred);
                }
                else
                {
                    sqlCmd = "INSERT INTO logins (origin_url, action_url, username_element, username_value, " +
                    "password_element, password_value, submit_element, signon_realm, date_created, blacklisted_by_user, " +
                    "scheme, password_type, times_used, form_data, date_synced, display_name, icon_url, federation_url, skip_zero_click, " +
                    "generation_upload_status, possible_username_pairs, id, date_last_used, moving_blocked_for) VALUES" +
                    " (@origin_url, @action_url, @username_element, @username_value, @password_element, @password_value, @submit_element," +
                    "@signon_realm, @date_created, @blacklisted_by_user, @scheme, " +
                    "@password_type, @times_used, @form_data, @date_synced, @display_name, @icon_url, @federation_url, " +
                    "@skip_zero_click, @generation_upload_status, @possible_username_pairs, @id, @date_last_used, @moving_blocked_for)";
                    cmd = new SQLiteCommand(sqlCmd, con);
                }

                cmd.Parameters.AddWithValue("@origin_url", c.origin_url);
                cmd.Parameters.AddWithValue("@action_url", c.action_url);
                cmd.Parameters.AddWithValue("@username_element", c.username_element);
                cmd.Parameters.AddWithValue("@username_value", c.username_value);
                cmd.Parameters.AddWithValue("@password_element", c.password_element);
                cmd.Parameters.AddWithValue("@password_value", c.password_value);
                cmd.Parameters.AddWithValue("@submit_element", c.submit_element);
                cmd.Parameters.AddWithValue("@signon_realm", c.signon_realm);
                cmd.Parameters.AddWithValue("@date_created", c.date_created);
                cmd.Parameters.AddWithValue("@blacklisted_by_user", c.blacklisted_by_user);
                cmd.Parameters.AddWithValue("@scheme", c.scheme);
                cmd.Parameters.AddWithValue("@password_type", c.password_type);
                cmd.Parameters.AddWithValue("@times_used", c.times_used);
                cmd.Parameters.AddWithValue("@form_data", c.form_data);
                cmd.Parameters.AddWithValue("@date_synced", c.date_synced);
                cmd.Parameters.AddWithValue("@display_name", c.display_name);
                cmd.Parameters.AddWithValue("@icon_url", c.icon_url);
                cmd.Parameters.AddWithValue("@federation_url", c.federation_url);
                cmd.Parameters.AddWithValue("@skip_zero_click", c.skip_zero_click);
                cmd.Parameters.AddWithValue("@generation_upload_status", c.generation_upload_status);
                cmd.Parameters.AddWithValue("@possible_username_pairs", c.possible_username_pairs);
                cmd.Parameters.AddWithValue("@id", c.id);
                cmd.Parameters.AddWithValue("@date_last_used", c.date_last_used);
                cmd.Parameters.AddWithValue("@moving_blocked_for", c.moving_blocked_for);

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

        private List<Item> ExportCookies()
        {
            List<Item> items = new List<Item>();

            byte[] keyBytes = GetStateKey(StateKeyText.Text);

            // initialize AES
            AesCrypto crypto = new AesCrypto(keyBytes);

            // open the Cookie db
            string cs = string.Format("Data Source={0};", this.inputFile);
            string stm = "SELECT creation_utc, host_key, name, value, " +
                "path, expires_utc, is_secure, is_httponly, last_access_utc, " +
                "has_expires, is_persistent, priority, encrypted_value, " +
                "samesite, source_scheme FROM cookies ORDER BY host_key;";
            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();

            SQLiteCommand cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            int exceptionsCount = 0;

            if (reader.HasRows)
            {
                bool ret = true;
                int errCount = 0;

                while (ret)
                {
                    byte[] encrypted_value;
                    try
                    {
                        ret = reader.Read();
                        encrypted_value = (byte[])reader["encrypted_value"];
                    }
                    catch
                    {
                        errCount++;

                        if (errCount > 3)
                        {
                            MessageBox.Show("Some cookies could not be imported.", "Warning");
                            break;
                        }

                        continue;
                    }

                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            if (exceptionsCount < 3)
                            {
                                MessageBox.Show(e.Message);
                                exceptionsCount++;
                            }
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    Cookie cookie = new Cookie
                    {
                        creation_utc = reader.GetInt64(0),
                        host_key = reader.GetString(1),
                        name = reader.GetString(2),
                        value = reader.GetString(3),
                        path = reader.GetString(4),
                        expires_utc = reader.GetInt64(5),
                        is_secure = reader.GetBoolean(6),
                        is_httponly = reader.GetBoolean(7),
                        last_access_utc = reader.GetInt64(8),
                        has_expires = reader.GetBoolean(9),
                        is_persistent = reader.GetBoolean(10),
                        priority = reader.GetInt16(11),
                        encrypted_value = encrypted_value,
                        samesite = reader.GetBoolean(13),
                        source_scheme = reader.GetInt16(14),
                        decrypted_value = decrypted_value
                    };
                    items.Add(cookie);
                }
            }
            else
            {
                Console.WriteLine("No rows found.");
            }

            try
            {
                reader.Close();
            }
            catch
            { }

            if (items.Count() == 0)
            {
                MessageBox.Show("No cookies were exported from specified input database!", "Error");
            }

            return items;
        }

        private List<Item> ExportLogins()
        {
            List<Item> items = new List<Item>();

            byte[] keyBytes = GetStateKey(StateKeyText.Text);

            // initialize AES
            AesCrypto crypto = new AesCrypto(keyBytes);

            // open the Cookie db
            string cs = string.Format("Data Source={0};", this.inputFile);
            string stm = "SELECT * FROM logins ORDER BY origin_url;";
            SQLiteConnection con = new SQLiteConnection(cs);
            con.Open();

            SQLiteCommand cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            int exceptionsCount = 0;

            int originUrlId = reader.GetOrdinal("origin_url");
            int actionUrlId = reader.GetOrdinal("action_url");
            int usernameElementId = reader.GetOrdinal("username_element");
            int usernameValueId = reader.GetOrdinal("username_value");
            int passwordElementId = reader.GetOrdinal("password_element");
            int submitElement = reader.GetOrdinal("submit_element");
            int signonRealmId = reader.GetOrdinal("signon_realm");
            int preferredId = reader.GetOrdinal("preferred");
            int dateCreatedId = reader.GetOrdinal("date_created");
            int blacklistedByUserId = reader.GetOrdinal("blacklisted_by_user");
            int schemeId = reader.GetOrdinal("scheme");
            int passwordTypeId = reader.GetOrdinal("password_type");
            int timesUsedId = reader.GetOrdinal("times_used");
            int dateSyncedId = reader.GetOrdinal("date_synced");
            int displayNameId = reader.GetOrdinal("display_name");
            int iconUrl = reader.GetOrdinal("icon_url");
            int federationUrlId = reader.GetOrdinal("federation_url");
            int skipZeroClickId = reader.GetOrdinal("skip_zero_click");
            int generationUploadStatusId = reader.GetOrdinal("generation_upload_status");
            int idId = reader.GetOrdinal("id");
            int dateLastUsedId = reader.GetOrdinal("date_last_used");

            if (reader.HasRows)
            {
                bool ret = true;
                int errCount = 0;

                while (ret)
                {
                    byte[] encrypted_value;
                    try
                    {
                        ret = reader.Read();
                        encrypted_value = (byte[])reader["password_value"];
                    }
                    catch
                    {
                        errCount++;

                        if (errCount > 3)
                        {
                            MessageBox.Show("Some logins could not be imported.", "Warning");
                            break;
                        }

                        continue;
                    }

                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            if (exceptionsCount < 3)
                            {
                                MessageBox.Show(e.Message);
                                exceptionsCount++;
                            }
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    Login login = new Login
                    {
                        origin_url = originUrlId == -1 ? "" : reader.GetString(originUrlId),
                        action_url = actionUrlId == -1 ? "" : reader.GetString(actionUrlId),
                        username_element = usernameElementId == -1 ? "" : reader.GetString(usernameElementId),
                        username_value = usernameValueId == -1 ? "" : reader.GetString(usernameValueId),
                        password_element = passwordElementId == -1 ? "" : reader.GetString(passwordElementId),
                        password_value = encrypted_value,
                        submit_element = submitElement == -1 ? "" : reader.GetString(submitElement),
                        signon_realm = signonRealmId == -1 ? "" : reader.GetString(signonRealmId),
                        preferred = preferredId == -1 ? 0 : reader.GetInt32(preferredId),
                        date_created = dateCreatedId == -1 ? 0 : reader.GetInt32(dateCreatedId),
                        blacklisted_by_user = blacklistedByUserId == -1 ? 0 : reader.GetInt32(blacklistedByUserId),
                        scheme = schemeId == -1 ? 0 : reader.GetInt32(schemeId),
                        password_type = passwordTypeId == -1 ? 0 : reader.GetInt32(passwordTypeId),
                        times_used = timesUsedId == -1 ? 0 : reader.GetInt32(timesUsedId),
                        form_data = Convert.IsDBNull(reader["form_data"]) ? null : (byte[])reader["form_data"],
                        date_synced = dateSyncedId == -1 ? 0 : reader.GetInt32(dateSyncedId),
                        display_name = displayNameId == -1 ? "" : reader.GetString(displayNameId),
                        icon_url = iconUrl == -1 ? "" : reader.GetString(iconUrl),
                        federation_url = federationUrlId == -1 ? "" : reader.GetString(federationUrlId),
                        skip_zero_click = skipZeroClickId == -1 ? 0 : reader.GetInt32(skipZeroClickId),
                        generation_upload_status = generationUploadStatusId == -1 ? 0 : reader.GetInt32(generationUploadStatusId),
                        possible_username_pairs = Convert.IsDBNull(reader["possible_username_pairs"]) ? null : (byte[])reader["possible_username_pairs"],
                        id = idId == -1 ? 0 : reader.GetInt32(idId),
                        date_last_used = dateLastUsedId == -1 ? 0 : reader.GetInt32(dateLastUsedId),
                        moving_blocked_for = Convert.IsDBNull(reader["moving_blocked_for"]) ? null : (byte[])reader["moving_blocked_for"],
                        decrypted_password_value = decrypted_value
                    };
                    items.Add(login);
                }
            }
            else
            {
                Console.WriteLine("No rows found.");
            }
            reader.Close();

            if (items.Count() == 0)
            {
                MessageBox.Show("No logins were exported from specified input database!", "Error");
            }

            return items;
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
                if (BitConverter.ToUInt32(content, 0) != 2964713758)
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
                        MessageBox.Show("Will assume data provided is a password");
                    this.password = PasswordOrPVK.Text;
                    return true;
                }
                else
                {
                    // could still be a base64 pvk, lets validate
                    try
                    {
                        byte[] content = Convert.FromBase64String(PasswordOrPVK.Text);
                        if (BitConverter.ToUInt32(content, 0) != 2964713758)
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
            bool isValidDirectory = false;
            foreach (string file in Directory.GetFiles(folderName, "*", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    byte[] content = File.ReadAllBytes(file);
                    if (content.Length == 0x2E4)
                    {
                        isValidDirectory = true;
                    }
                    if (isValidDirectory)
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }
            }
            MessageBox.Show("Selected directory does not contain any DPAPI masterkeys");
            return false;
        }

        private void DPAPIMasterKey_Browse(object sender, RoutedEventArgs e)
        {
            VistaFolderBrowserDialog dlg = new VistaFolderBrowserDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                if (ValidateMasterKeyDirectory(dlg.SelectedPath))
                    TextBox_Masterkey.Text = dlg.SelectedPath;
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
    }
}
