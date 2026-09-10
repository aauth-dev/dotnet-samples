using System;
using System.Collections.Generic;
using System.Net.Http;

namespace AAuth;

internal sealed class OwnedPipelineHandler(HttpMessageHandler inner, IReadOnlyList<IDisposable> resources) : DelegatingHandler(inner)
{
    private bool _disposed;

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            try { base.Dispose(true); }
            finally
            {
                foreach (var resource in resources) resource.Dispose();
            }
            return;
        }
        if (!disposing) base.Dispose(false);
    }
}