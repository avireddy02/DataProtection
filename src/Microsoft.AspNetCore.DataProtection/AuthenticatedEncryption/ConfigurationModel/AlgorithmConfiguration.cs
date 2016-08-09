// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    public abstract class AlgorithmConfiguration
    {
        internal const int KDK_SIZE_IN_BYTES = 512 / 8;

        /// <summary>
        /// Creates a new <see cref="IAuthenticatedEncryptorDescriptor"/> instance based on this
        /// configuration. The newly-created instance contains unique key material and is distinct
        /// from all other descriptors created by the <see cref="CreateNewDescriptor"/> method.
        /// </summary>
        /// <returns>A unique <see cref="IAuthenticatedEncryptorDescriptor"/>.</returns>
        public abstract IAuthenticatedEncryptorDescriptor CreateNewDescriptor();

        /// <summary>
        /// Creates a new <see cref="IAuthenticatedEncryptorDescriptor"/> instance from this configuration
        /// fiven specific secret key material.
        /// </summary>
        /// <remarks>
        /// This type is not public because we don't want to lock ourselves into a contract stating
        /// that a descriptor is simply a configuration plus a single serializable, reproducible secret.
        /// </remarks>
        internal abstract IAuthenticatedEncryptorDescriptor CreateDescriptorFromSecret(ISecret secret);

        /// <summary>
        /// Performs a self-test of the algorithm specified by the configuration object.
        /// </summary>
        internal abstract void Validate();
    }
}
