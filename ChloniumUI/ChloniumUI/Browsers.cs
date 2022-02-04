using System;
using System.Collections.Generic;

namespace ChloniumUI
{
    class Browsers
    {
        public class BrowserConfig
        {
            public string BrowserName { get; set; }
            public string ProcessName { get; set; }
            public string CookieFile { get; set; }
            public string LoginFile { get; set; }
            public string LocalState { get; set; }
        }

        public static List<BrowserConfig> browserConfigs = new List<BrowserConfig>
        {
            new BrowserConfig
            {
                BrowserName = "Chrome",
                ProcessName = "chrome",
                CookieFile = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                LoginFile = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", Environment.GetEnvironmentVariable("USERPROFILE")),
                LocalState = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
            new BrowserConfig
            {
                BrowserName = "Edge (Chromium)",
                ProcessName = "msedge",
                CookieFile = string.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                LoginFile = string.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", Environment.GetEnvironmentVariable("USERPROFILE")),
                LocalState = string.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
            new BrowserConfig
            {
                BrowserName = "Vivaldi",
                ProcessName = "vivaldi",
                CookieFile = string.Format("{0}\\AppData\\Local\\Vivaldi\\User Data\\Default\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                LoginFile = string.Format("{0}\\AppData\\Local\\Vivaldi\\User Data\\Default\\Login Data", Environment.GetEnvironmentVariable("USERPROFILE")),
                LocalState = string.Format("{0}\\AppData\\Local\\Vivaldi\\User Data\\Local State", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
        };
    }
}
