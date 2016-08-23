﻿using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace JavaWindowsCASync
{
    class Program
    {
        static void Main(string[] args)
        {
            List<string> keyStoreFiles = new List<string>();
            // find all java installations
            string[] regSearchKeys = new string[]
            {
                @"SOFTWARE\JavaSoft\Java Runtime Environment",
                @"SOFTWARE\JavaSoft\Java Development Kit",
                @"SOFTWARE\Wow6432Node\JavaSoft\Java Runtime Environment",
                @"SOFTWARE\Wow6432Node\JavaSoft\Java Development Kit",
            };

            foreach (string regSearchKey in regSearchKeys) {
                RegistryKey jreReg = Registry.LocalMachine.OpenSubKey(regSearchKey);
                if (jreReg != null)
                {
                    string[] jreVersionsNames = jreReg.GetSubKeyNames();
                    foreach (string jreVersionName in jreVersionsNames)
                    {
                        RegistryKey jreVersionKey = jreReg.OpenSubKey(jreVersionName);
                        if (jreVersionKey != null)
                        {
                            object value = jreVersionKey.GetValue("JavaHome");
                            if (value is string)
                            {
                                string cacertsFile = value as string;
                                if(regSearchKey.Contains("Development"))
                                {
                                    cacertsFile = Path.Combine(cacertsFile, "jre");
                                }
                                cacertsFile = Path.Combine(cacertsFile, "lib" + Path.DirectorySeparatorChar + "security" + Path.DirectorySeparatorChar + "cacerts");
                                if (!keyStoreFiles.Contains(cacertsFile))
                                {
                                    keyStoreFiles.Add(cacertsFile);
                                }
                            }
                        }
                    }
                }
            }
            
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            RSACryptoServiceProvider.UseMachineKeyStore = true;
            store.Open(OpenFlags.ReadOnly | OpenFlags.IncludeArchived);
            foreach(X509Certificate2 cert in store.Certificates)
            {
                byte[] certData = cert.Export(X509ContentType.Cert);
                string certTempFile = Path.Combine(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    cert.Thumbprint + ".cer"
                );

                Console.WriteLine("Processing cert: " + cert.Subject);
                File.WriteAllBytes(certTempFile, certData);

                foreach (string keyStoreFile in keyStoreFiles)
                {
                    Process p = Process.Start(@"C:\Program Files (x86)\Java\jre1.8.0_45\bin\keytool.exe", "-importcert -file " + certTempFile + " -keystore \"" + keyStoreFile + "\" -storepass changeit -alias " + cert.Thumbprint + " -noprompt");
                    p.WaitForExit();
                }
                File.Delete(certTempFile);
            }
            Console.ReadKey();
        }
    }
}
