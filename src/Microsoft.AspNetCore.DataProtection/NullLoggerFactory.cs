// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// An <see cref="ILoggerFactory"/> that provides a logger that no ops.
    /// </summary>
    public class NullLoggerFactory : ILoggerFactory
    {
        public static readonly NullLoggerFactory Instance = new NullLoggerFactory();

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName)
        {
            return NullLogger.Instance;
        }

        public void Dispose()
        {
        }

        private class NullLogger : ILogger
        {
            public static readonly NullLogger Instance = new NullLogger();

            public IDisposable BeginScope<TState>(TState state)
            {
                return NullDisposable.Instance;
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return false;
            }

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
            }

            private class NullDisposable : IDisposable
            {
                public static readonly NullDisposable Instance = new NullDisposable();

                public void Dispose()
                {
                    // intentionally does nothing
                }
            }
        }
    }
}
