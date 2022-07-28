using System.Text;

namespace ChloniumUI
{
    class Item { }

    class Cookie : Item
    {
        public long creation_utc;
        public string host_key;
        public string name;
        public string value;
        public string path;
        public long expires_utc;
        public bool is_secure;
        public bool is_httponly;
        public long last_access_utc;
        public long last_update_utc;
        public bool has_expires;
        public bool is_persistent;
        public short priority;
        public byte[] encrypted_value;
        public bool samesite;
        public short source_scheme;
        public short source_port;
        public short is_same_party;
        public byte[] decrypted_value;

        public override string ToString()
        {
            return $"{creation_utc},{host_key},{name},{value}," +
                $"{path},{expires_utc},{is_secure},{is_httponly}," +
                $"{last_access_utc},{last_update_utc},{has_expires},{is_persistent}," +
                $"{priority},{Encoding.UTF8.GetString(decrypted_value)},{samesite},{source_scheme},{last_update_utc}";
        }
    }

    class Login : Item
    {
        public string origin_url;
        public string action_url;
        public string username_element;
        public string username_value;
        public string password_element;
        public byte[] password_value;
        public string submit_element;
        public string signon_realm;
        public int preferred;
        public int date_created;
        public int blacklisted_by_user;
        public int scheme;
        public int password_type;
        public int times_used;
        public byte[] form_data;
        public int date_synced;
        public string display_name;
        public string icon_url;
        public string federation_url;
        public int skip_zero_click;
        public int generation_upload_status;
        public byte[] possible_username_pairs;
        public int id;
        public int date_last_used;
        public byte[] moving_blocked_for;
        public byte[] decrypted_password_value;

        public override string ToString()
        {
            return $"{origin_url},{username_value},{Encoding.UTF8.GetString(decrypted_password_value)}";
        }
    }
}
