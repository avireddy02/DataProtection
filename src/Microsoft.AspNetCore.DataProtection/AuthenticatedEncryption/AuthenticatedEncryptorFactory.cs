// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
    public class AuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly ILoggerFactory _loggerFactory;

        public AuthenticatedEncryptorFactory(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory;
        }

        public IAuthenticatedEncryptor CreateEncryptorInstance(IKey key)
        {
            var descriptor = key.Descriptor as AuthenticatedEncryptorDescriptor;
            if (descriptor == null)
            {
                return null;
            }

            return CreateAuthenticatedEncryptorInstance(descriptor.MasterKey, descriptor.Settings);
        }

        internal IAuthenticatedEncryptor CreateAuthenticatedEncryptorInstance(
            ISecret secret,
            AuthenticatedEncryptorConfiguration authenticatedConfiguration)
        {
            if (authenticatedConfiguration == null)
            {
                return null;
            }

            if (authenticatedConfiguration.IsGcmAlgorithm())
            {
                // GCM requires CNG, and CNG is only supported on Windows.
                if (!OSVersionUtil.IsWindows())
                {
                    throw new PlatformNotSupportedException(Resources.Platform_WindowsRequiredForGcm);
                }

                var configuration = new CngGcmAuthenticatedEncryptorConfiguration()
                {
                    EncryptionAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                    EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits()
                };

                return new CngGcmAuthenticatedEncryptorFactory(_loggerFactory).CreateAuthenticatedEncryptorInstance(secret, configuration);
            }
            else
            {
                if (OSVersionUtil.IsWindows())
                {
                    // CNG preferred over managed implementations if running on Windows
                    var configuration = new CngCbcAuthenticatedEncryptorConfiguration()
                    {
                        EncryptionAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromEncryptionAlgorithm(),
                        EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                        HashAlgorithm = authenticatedConfiguration.GetBCryptAlgorithmNameFromValidationAlgorithm()
                    };

                    return new CngCbcAuthenticatedEncryptorFactory(_loggerFactory).CreateAuthenticatedEncryptorInstance(secret, configuration);
                }
                else
                {
                    // Use managed implementations as a fallback
                    var configuration = new ManagedAuthenticatedEncryptorConfiguration()
                    {
                        EncryptionAlgorithmType = authenticatedConfiguration.GetManagedTypeFromEncryptionAlgorithm(),
                        EncryptionAlgorithmKeySize = authenticatedConfiguration.GetAlgorithmKeySizeInBits(),
                        ValidationAlgorithmType = authenticatedConfiguration.GetManagedTypeFromValidationAlgorithm()
                    };

                    return new ManagedAuthenticatedEncryptorFactory(_loggerFactory).CreateAuthenticatedEncryptorInstance(secret, configuration);
                }
            }
        }
    }
}
