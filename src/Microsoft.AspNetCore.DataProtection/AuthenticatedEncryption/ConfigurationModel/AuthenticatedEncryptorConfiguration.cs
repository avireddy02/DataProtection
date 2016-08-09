// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// Represents a generalized authenticated encryption mechanism.
    /// </summary>
    public sealed class AuthenticatedEncryptorConfiguration : AlgorithmConfiguration
    {
        /// <summary>
        /// The algorithm to use for symmetric encryption (confidentiality).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="EncryptionAlgorithm.AES_256_CBC"/>.
        /// </remarks>
        public EncryptionAlgorithm EncryptionAlgorithm { get; set; } = EncryptionAlgorithm.AES_256_CBC;

        /// <summary>
        /// The algorithm to use for message authentication (tamper-proofing).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="ValidationAlgorithm.HMACSHA256"/>.
        /// This property is ignored if <see cref="EncryptionAlgorithm"/> specifies a 'GCM' algorithm.
        /// </remarks>
        public ValidationAlgorithm ValidationAlgorithm { get; set; } = ValidationAlgorithm.HMACSHA256;

        public override IAuthenticatedEncryptorDescriptor CreateNewDescriptor()
        {
            return CreateDescriptorFromSecret(Secret.Random(KDK_SIZE_IN_BYTES));
        }

        internal override IAuthenticatedEncryptorDescriptor CreateDescriptorFromSecret(ISecret secret)
        {
            return new AuthenticatedEncryptorDescriptor(this, secret);
        }

        internal override void Validate()
        {
            var factory = new AuthenticatedEncryptorFactory(DataProtectionProviderFactory.GetDefaultLoggerFactory());
            // Run a sample payload through an encrypt -> decrypt operation to make sure data round-trips properly.
            var encryptor = factory.CreateAuthenticatedEncryptorInstance(Secret.Random(512 / 8), this);
            try
            {
                encryptor.PerformSelfTest();
            }
            finally
            {
                (encryptor as IDisposable)?.Dispose();
            }
        }

        public bool IsGcmAlgorithm()
        {
            return (EncryptionAlgorithm.AES_128_GCM <= EncryptionAlgorithm && EncryptionAlgorithm <= EncryptionAlgorithm.AES_256_GCM);
        }

        public int GetAlgorithmKeySizeInBits()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                    return 128;

                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_192_GCM:
                    return 192;

                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_256_GCM:
                    return 256;

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public string GetBCryptAlgorithmNameFromEncryptionAlgorithm()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return Constants.BCRYPT_AES_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public string GetBCryptAlgorithmNameFromValidationAlgorithm()
        {
            switch (ValidationAlgorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return Constants.BCRYPT_SHA256_ALGORITHM;

                case ValidationAlgorithm.HMACSHA512:
                    return Constants.BCRYPT_SHA512_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(ValidationAlgorithm));
            }
        }

        public Type GetManagedTypeFromEncryptionAlgorithm()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return typeof(Aes);

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public Type GetManagedTypeFromValidationAlgorithm()
        {
            switch (ValidationAlgorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return typeof(HMACSHA256);

                case ValidationAlgorithm.HMACSHA512:
                    return typeof(HMACSHA512);

                default:
                    throw new ArgumentOutOfRangeException(nameof(ValidationAlgorithm));
            }
        }
    }
}
