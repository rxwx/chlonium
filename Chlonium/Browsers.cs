using System;
using System.Collections.Generic;

namespace Chlonium
{
    class Browsers
    {
        public class BrowserConfig
        {
            public string browserName { get; set; }
            public string processName { get; set; }
            public string cookieFile { get; set; }
            public string localState { get; set; }
        }

        public static List<BrowserConfig> browserConfigs = new List<BrowserConfig>
        {
            new BrowserConfig
            {
                browserName = "Chrome",
                processName = "chrome",
                cookieFile = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                localState = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
            new BrowserConfig
            {
                browserName = "Edge (Chromium)",
                processName = "msedge",
                cookieFile = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                localState = string.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
            new BrowserConfig
            {
                browserName = "Vivaldi",
                processName = "vivaldi",
                cookieFile = string.Format("{0}\\AppData\\Local\\Vivaldi\\User Data\\Default\\Cookies", Environment.GetEnvironmentVariable("USERPROFILE")),
                localState = string.Format("{0}\\AppData\\Local\\Vivaldi\\User Data", Environment.GetEnvironmentVariable("USERPROFILE"))
            },
        };
    }
}
