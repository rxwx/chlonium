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
        private string cookieFile = String.Empty;

        private BrowserConfig browser = null;

        public MainWindow()
        {
            InitializeComponent();

            foreach (var browser in browserConfigs)
            {
                if (File.Exists(browser.cookieFile))
                {
                    ComboBox.Items.Add(browser);
                }
            }
        }

        private bool ImportExportCheck()
        {
            if (String.IsNullOrEmpty(browser.cookieFile) || !File.Exists(browser.cookieFile))
            {
                MessageBox.Show("Enter a valid cookie file path");
                return false;
            }
            if (String.IsNullOrEmpty(MasterKeyText.Text))
            {
                MessageBox.Show("Enter a valid master key");
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
            if (Process.GetProcessesByName(browser.processName).Length > 0)
            {
                MessageBox.Show($"{browser.processName} is running. Please close it first", "Error");
                return;
            }

            // initialize AES
            var crypto = new AesCrypto(browser.localState);

            string backupFile = String.Format("Cookies_{0}.bak", DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss"));
            File.Copy(browser.cookieFile, backupFile, true);

            List<Cookie> items = ExportItems();

            // re-encrypt all items
            foreach (Cookie c in items)
            {
                c.encrypted_value = crypto.Encrypt(c.decrypted_value);
            }
            ImportItems(items);
            MessageBox.Show("Imported!");
        }

        private void CookieFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                string filename = dlg.FileName;
                this.cookieFile = filename;

                // Check file is sqlite3
                byte[] fileMagic = File.ReadAllBytes(this.cookieFile).Take(15).ToArray();
                if (Encoding.UTF8.GetString(fileMagic) != "SQLite format 3")
                {
                    MessageBox.Show("Selected file is not a Cookie database", "Error");
                    this.cookieFile = String.Empty;
                    return;
                }
                TextBox_CookieFile.Text = filename;
            }
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            if (!ImportExportCheck())
                return;

            string outputFile = String.Empty;
            SaveFileDialog dlg = new SaveFileDialog
            {
                FileName = "cookies",
                DefaultExt = ".txt",
                Filter = "Text File|*.txt"
            };

            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                outputFile = dlg.FileName;
            }

            // export cookies to file
            List<Cookie> exportedItems = ExportItems();
            using (var writer = File.CreateText(outputFile))
            {
                foreach (Cookie c in exportedItems)
                {
                    writer.WriteLine(c);
                }
            }
            MessageBox.Show("Exported!");
        }

        private void ImportItems(List<Cookie> items)
        {
            // SCARY STUFF!! Make sure we take a backup
            string cs = string.Format("Data Source={0};", browser.cookieFile);

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

        private List<Cookie> ExportItems()
        {
            List<Cookie> items = new List<Cookie>();

            // initialize AES
            var crypto = new AesCrypto(Convert.FromBase64String(MasterKeyText.Text));

            // open the Cookie db
            string cs = string.Format("Data Source={0};", this.cookieFile);
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

        private void ComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            this.browser = (BrowserConfig)ComboBox.SelectedItem;
        }
    }
}
