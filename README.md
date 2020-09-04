# Chlonium
Chlonium is an application designed for cloning Chromium Cookies.

From Chromium 80 and upwards, cookies are encrypted using AES-256 GCM, with a master key which is stored in the Local State file. This master key is encrypted using DPAPI. This is a change from older versions, which used DPAPI to encrypt each cookie item in the cookie database. What this means is that if you have the master key, you will always be able to decrypt the cookie database offline, without needing continual access to DPAPI keys.

This essentially makes cookie databases "portable", meaning they can be moved from machine to machine, provided you have dumped the master key. The cookies themselves need to be re-encrypted when they are imported, because the master keys will differ on each user profile & machine. This can be done using the same process as decryption, by first decrypting the master key from the "target" browser, and then re-encrypting each item with the new key.

The project is written in C# and has two separate components to it. The first component, `chlonium.exe` is the collector binary. It simply decrypts the master key and prints it. Keep a note of this key and you can decrypt cookies in the future by downloading the `Cookies` database file whenever you need updated cookies. By default it will attempt to decrypt the Chrome master key. If you want to dump the master key for another browser (e.g. Edge), you can specify a path to the key.

For example:

```
> Chlonium.exe "c:\users\user\AppData\Local\Microsoft\Edge\User Data\Local State"
[+] Masterkey = 3Cms3YxFXVyJRUbulYCnxqY2dO/jubDkYBQBoYIvqfc=
```

The second component, `ChloniumUI.exe` is the "importer" tool. This takes care of decrypting a given Cookies database file with a given master key, re-encrypting the values with the current users master key, and importing the cookies into your chosen browser. You run this on the machine you want to import the cookies into.

To use it, run the `ChloniumUI.exe` executable. Enter the previously extracted master key, choose the `Cookies` file you wish to import, and select the browser you wish the import the cookies into. Now click "Import Cookies" and the cookies will be imported.

`ChloniumUI` currently supports three Chromium based browsers: Edge, Chrome and Vivaldi. Additional browsers can be added in `Browsers.cs`. This adds the unintended benefit of being able to import an Edge cookie file into Chrome, or vice versa (for example), though it's probably not a good idea given that the user-agent will mismatch.

**Important Note**: When importing the cookie file into your browser, all old cookies are cleared! A backup is copied to the current directory (with relevant time stamp). If you need to restore the previous cookies, simply copy the backup file over the `Cookies` file.

## Why

Tools such as [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi) and [SharpChromium](https://github.com/djhohnstein/SharpChromium) already have the capability to dump Chrome 80 cookies, why another tool?

This tool is specifically aimed at making it easier to *import* cookies into another browser. Whilst these tools do a great job of dumping Chromium cookies (and more!), I wanted to have something that let me easily import into another browser. Third-party cookie manager plugins exist, but I've always found these fiddly and prone to failure. `CloniumUI` is designed to make this process easier by importing the cookies directly into your browser's sqlite database.

Whilst this project comes with the `chlonium.exe` collector, which aids in dumping the master key, this is really only an example. Other tools such as Mimikatz will also dump the master key for you, in a potentially stealthier way (depending on your operating environment, execution method etc.). Additionally, [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#statekeys) will allow you to decrypt the Chromium master key file if you have DPAPI master keys, current password, or domain backup key - allowing you to dump cookies remotely over SMB!

When carrying out Red Teaming, I sometimes need to dump a user's cookies multiple times over a sustained period (e.g. daily/weekly). Using a .NET assembly, Reflective DLL or other in-memory execution technique to extract individual cookies from the cookie file directly on the target system is unneccesary and exposes the operator to increased risk of detection. Instead you can simply dump the master key once, and copy the `Cookies` database file off whenever you need fresh cookies, without requiring additional execution.

## Demo

See [here](https://vimeo.com/452632559?quality=1080p) for a video demo.

## Password Import/Export

`CloniumUI` also supports password import and export. To use this feature, simply supply the `Login Data` database path instead of the `Cookies` db, along with the master key, and select the browser you wish to import them into (for export this doesn't matter). This allows you to either export passwords in plaintext to a file, or import them into your browser. As with cookies, you can import Chrome passwords into Edge, Edge passwords into Vivaldi etc.

## Detection

Set a SACL on the Chrome `Local State` and `Cookies` files (as well as other sensitive files such as `Login Data` and `History`). Look for suspicious (e.g. non browser related) processes opening any of these files.

Take a look at this great [blog post](https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950) from @cryps1s about setting up SACLs for detection.

For AV vendors that use a file system filter driver, consider blocking non browser-related processes from opening these files. e.g. PowerShell opening the `Cookies` file.

## References

* https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi
* https://github.com/djhohnstein/SharpChromium
* https://github.com/GhostPack/SharpDPAPI
* https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
* https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950
