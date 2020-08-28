using System.Text;

namespace ChloniumUI
{
    class Cookie
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
        public bool has_expires;
        public bool is_persistent;
        public short priority;
        public byte[] encrypted_value;
        public bool samesite;
        public short source_scheme;
        public byte[] decrypted_value;


        public override string ToString()
        {
            return $"{creation_utc},{host_key},{name},{value}," +
                $"{path},{expires_utc},{is_secure},{is_httponly}," +
                $"{last_access_utc},{has_expires},{is_persistent}," +
                $"{priority},{Encoding.UTF8.GetString(decrypted_value)},{samesite},{source_scheme}";
        }
    }
}
