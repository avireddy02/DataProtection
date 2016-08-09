// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;

namespace NonDISample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // get the path to %LOCALAPPDATA%\myapp-keys
            var destFolder = Path.Combine(
                Environment.GetEnvironmentVariable("LOCALAPPDATA"),
                "myapp-keys");

            // instantiate the data protection system at this folder
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(destFolder),
                configuration =>
                {
                    configuration.SetApplicationName("my app name");
                    configuration.ProtectKeysWithDpapi();
                });

            var protector = dataProtectionProvider.CreateProtector("Program.No-DI");

            // protect the payload
            var protectedPayload = protector.Protect("Hello World!");
            Console.WriteLine($"Protect returned: {protectedPayload}");

            // unprotect the payload
            var unprotectedPayload = protector.Unprotect(protectedPayload);
            Console.WriteLine($"Unprotect returned: {unprotectedPayload}");
        }
    }
}
