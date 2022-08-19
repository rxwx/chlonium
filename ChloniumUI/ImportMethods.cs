using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using static ChloniumUI.Browsers;

namespace ChloniumUI
{
    internal class ImportMethods
    {
        public static Dictionary<Type, string> ListImporters()
        {
            // Populate list of available importers
            Dictionary<Type, string> importers = new Dictionary<Type, string>();
            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());
            var importerTypes = types.Where(p => typeof(Importer).IsAssignableFrom(p) && !p.IsAbstract);
            foreach (var type in importerTypes)
            {
                object obj = Activator.CreateInstance(type, new object[] { null, null });
                string name = (string)obj.GetType().GetProperty("Name").GetValue(obj);
                importers.Add(type, name);
            }
            return importers;
        }

        internal abstract class Importer
        {
            public abstract string Name { get; }

            public BrowserConfig Browser { get; }

            public byte[] StateKey { get; }

            public abstract void ImportCookies(List<Item> items);

            public abstract void ImportLogins(List<Item> items);

            public override string ToString()
            {
                return this.Name;
            }

            public Importer(BrowserConfig browser, byte[] stateKey)
            {
                this.Browser = browser;
                this.StateKey = stateKey;
            }
        }

        internal class DatabaseImporter : Importer
        {
            public DatabaseImporter(BrowserConfig browser, byte[] stateKey): base(browser, stateKey)
            {
            }

            public override string Name => "Database Importer";

            public override void ImportCookies(List<Item> items)
            {
                // SCARY STUFF!! Make sure we take a backup
                string cs = string.Format("Data Source={0};", Browser.CookieFile);

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

            public override void ImportLogins(List<Item> items)
            {
                // SCARY STUFF!! Make sure we take a backup
                string cs = string.Format("Data Source={0};", Browser.LoginFile);

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
        }

        internal class StateKeyImporter : Importer
        {
            public StateKeyImporter(BrowserConfig browser, byte[] stateKey): base(browser, stateKey)
            {
            }

            public override string Name => "StateKey Importer";

            public void ImportStateKey()
            {
                // Replace State Key with provided key (re-encrypted with DPAPI)
                // Note: this will stop old cookies from decrypting properly
                // If you want to restore old cookies, you'll need to restore the Local State backup too

                string localState = File.ReadAllText(Browser.LocalState);
                Regex r = new Regex("encrypted_key\":\"([a-z0-9+\\/=]+)\"", RegexOptions.IgnoreCase);

                if (!r.IsMatch(localState))
                {
                    Console.WriteLine("[X] Couldn't find encrypted_key");
                    return;
                }

                string oldKey = r.Matches(localState)[0].Groups[1].Value;
                byte[] protectedKey = ProtectedData.Protect(StateKey, null, DataProtectionScope.CurrentUser);
                byte[] prefixedKey = new byte[5 + protectedKey.Length];
                Array.Copy(Encoding.ASCII.GetBytes("DPAPI"), prefixedKey, 5);
                Array.Copy(protectedKey, 0, prefixedKey, 5, protectedKey.Length);
                File.WriteAllText(Browser.LocalState, localState.Replace(oldKey, Convert.ToBase64String(prefixedKey)));
            }

            public override void ImportCookies(List<Item> items)
            {
                ImportStateKey();
            }

            public override void ImportLogins(List<Item> items)
            {
                ImportStateKey();
            }
        }
    }
}
