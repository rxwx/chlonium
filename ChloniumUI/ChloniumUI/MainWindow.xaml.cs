using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using System.IO;
using System.Data.SQLite;
using System.Diagnostics;
using static ChloniumUI.Browsers;

namespace ChloniumUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string inputFile;

        private string dbType;

        private BrowserConfig browser = null;

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

        private bool ImportExportCheck()
        {
            if (String.IsNullOrEmpty(TextBox_File.Text) || !File.Exists(TextBox_File.Text))
            {
                MessageBox.Show("Enter a valid database file path", "Error");
                return false;
            }
            if (String.IsNullOrEmpty(MasterKeyText.Text))
            {
                MessageBox.Show("Enter a valid master key", "Error");
                return false;
            }

            dbType = DetectDatabase();

            if (String.IsNullOrEmpty(dbType))
            {
                MessageBox.Show("Unknown database type", "Error");
                return false;
            }
            return true;
        }

        private void MasterKeyCheck_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] keyBytes = Convert.FromBase64String(MasterKeyText.Text);
                if (keyBytes.Length == 32)
                {
                    MessageBox.Show("Master key looks good");
                }
                else
                {
                    MessageBox.Show("Master key is not the correct length", "Error");
                }
            }
            catch
            {
                MessageBox.Show("Master key doesn't look right. Make sure it is base64 encoded.", "Error");
            }
        }

        private void Import_Click(object sender, RoutedEventArgs e)
        {
            if (!ImportExportCheck())
                return;

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

            switch (dbType)
            {
                case "cookies":
                    backupFile = String.Format("{0}_{1}.bak", Path.GetFileName(browser.CookieFile),
                        DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.CookieFile, backupFile, true);
                    items = ExportCookies();

                    // re-encrypt all items
                    foreach (Cookie c in items)
                    {
                        c.encrypted_value = crypto.Encrypt(c.decrypted_value);
                    }
                    ImportCookies(items);
                    break;
                case "logins":
                    backupFile = String.Format("{0}_{1}.bak", Path.GetFileName(browser.LoginFile),
                        DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
                    File.Copy(browser.LoginFile, backupFile, true);

                    items = ExportLogins();

                    // re-encrypt all items
                    foreach (Login i in items)
                    {
                        i.password_value = crypto.Encrypt(i.decrypted_password_value);
                    }
                    ImportLogins(items);
                    break;
                default:
                    return;
            }
            MessageBox.Show("Imported!");
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
                    MessageBox.Show("Selected file is not a Cookie database", "Error");
                    this.inputFile = String.Empty;
                    return;
                }
                TextBox_File.Text = filename;
            }
        }

        public string DetectDatabase()
        {
            string dbType = String.Empty;
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

            string outputFile = String.Empty;
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
            using (var writer = File.CreateText(outputFile))
            {
                foreach (var c in items)
                {
                    writer.WriteLine(c);
                }
            }
            MessageBox.Show("Exported!");
        }

        private void ImportCookies(List<Item> items)
        {
            // SCARY STUFF!! Make sure we take a backup
            string cs = string.Format("Data Source={0};", browser.CookieFile);

            var con = new SQLiteConnection(cs);
            con.Open();
            SQLiteCommand cmd = new SQLiteCommand("DELETE FROM cookies;", con);
            cmd.ExecuteNonQuery();

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
                    MessageBox.Show(ex.Message);
                }
            }
        }

        private void ImportLogins(List<Item> items)
        {
            // SCARY STUFF!! Make sure we take a backup
            string cs = string.Format("Data Source={0};", browser.LoginFile);

            var con = new SQLiteConnection(cs);
            con.Open();
            SQLiteCommand cmd = new SQLiteCommand("DELETE FROM logins;", con);
            cmd.ExecuteNonQuery();

            foreach (Login c in items)
            {
                cmd = new SQLiteCommand("INSERT INTO logins (origin_url, action_url, username_element, username_value, " +
                    "password_element, password_value, submit_element, signon_realm, preferred, date_created, blacklisted_by_user, " +
                    "scheme, password_type, times_used, form_data, date_synced, display_name, icon_url, federation_url, skip_zero_click, " +
                    "generation_upload_status, possible_username_pairs, id, date_last_used, moving_blocked_for) VALUES" +
                    " (@origin_url, @action_url, @username_element, @username_value, @password_element, @password_value, @submit_element," +
                    "@signon_realm, @preferred, @date_created, @blacklisted_by_user, @scheme, " +
                    "@password_type, @times_used, @form_data, @date_synced, @display_name, @icon_url, @federation_url, " +
                    "@skip_zero_click, @generation_upload_status, @possible_username_pairs, @id, @date_last_used, @moving_blocked_for)", con);
                cmd.Parameters.AddWithValue("@origin_url", c.origin_url);
                cmd.Parameters.AddWithValue("@action_url", c.action_url);
                cmd.Parameters.AddWithValue("@username_element", c.username_element);
                cmd.Parameters.AddWithValue("@username_value", c.username_value);
                cmd.Parameters.AddWithValue("@password_element", c.password_element);
                cmd.Parameters.AddWithValue("@password_value", c.password_value);
                cmd.Parameters.AddWithValue("@submit_element", c.submit_element);
                cmd.Parameters.AddWithValue("@signon_realm", c.signon_realm);
                cmd.Parameters.AddWithValue("@preferred", c.preferred);
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
                    MessageBox.Show(ex.Message);
                }
            }
        }

        private List<Item> ExportCookies()
        {
            List<Item> items = new List<Item>();

            // initialize AES
            var crypto = new AesCrypto(Convert.FromBase64String(MasterKeyText.Text));

            // open the Cookie db
            string cs = string.Format("Data Source={0};", this.inputFile);
            string stm = "SELECT creation_utc, host_key, name, value, " +
                "path, expires_utc, is_secure, is_httponly, last_access_utc, " +
                "has_expires, is_persistent, priority, encrypted_value, " +
                "samesite, source_scheme FROM cookies ORDER BY host_key;";
            var con = new SQLiteConnection(cs);
            con.Open();

            var cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            if (reader.HasRows)
            {
                while (reader.Read())
                {
                    byte[] encrypted_value = (byte[])reader["encrypted_value"];
                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            MessageBox.Show(e.Message);
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    var cookie = new Cookie
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
            reader.Close();
            return items;
        }

        private List<Item> ExportLogins()
        {
            List<Item> items = new List<Item>();

            // initialize AES
            var crypto = new AesCrypto(Convert.FromBase64String(MasterKeyText.Text));

            // open the Cookie db
            string cs = string.Format("Data Source={0};", this.inputFile);
            string stm = "SELECT * FROM logins ORDER BY origin_url;";
            var con = new SQLiteConnection(cs);
            con.Open();

            var cmd = new SQLiteCommand(stm, con);
            SQLiteDataReader reader = cmd.ExecuteReader();

            if (reader.HasRows)
            {
                while (reader.Read())
                {
                    byte[] encrypted_value = (byte[])reader["password_value"];
                    byte[] decrypted_value = null;

                    if (encrypted_value[0] == 'v' && encrypted_value[1] == '1' && encrypted_value[2] == '0')
                    {
                        try
                        {
                            decrypted_value = crypto.Decrypt(encrypted_value);
                        }
                        catch (Exception e)
                        {
                            MessageBox.Show(e.Message);
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: we could extract DPAPI keys too maybe
                        continue;
                    }

                    var login = new Login
                    {
                        origin_url = reader.GetString(0),
                        action_url = reader.GetString(1),
                        username_element = reader.GetString(2),
                        username_value = reader.GetString(3),
                        password_element = reader.GetString(4),
                        password_value = encrypted_value,
                        submit_element = reader.GetString(6),
                        signon_realm = reader.GetString(7),
                        preferred = reader.GetInt32(8),
                        date_created = reader.GetInt32(9),
                        blacklisted_by_user = reader.GetInt32(10),
                        scheme = reader.GetInt32(11),
                        password_type = reader.GetInt32(12),
                        times_used = reader.GetInt32(13),
                        form_data = (byte[])reader["form_data"],
                        date_synced = reader.GetInt32(15),
                        display_name = reader.GetString(16),
                        icon_url = reader.GetString(17),
                        federation_url = reader.GetString(18),
                        skip_zero_click = reader.GetInt32(19),
                        generation_upload_status = reader.GetInt32(20),
                        possible_username_pairs = (byte[])reader["possible_username_pairs"],
                        id = reader.GetInt32(22),
                        date_last_used = reader.GetInt32(23),
                        moving_blocked_for = (byte[])reader["moving_blocked_for"],
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
            return items;
        }

        private void ComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            this.browser = (BrowserConfig)ComboBox.SelectedItem;
        }
    }
}
