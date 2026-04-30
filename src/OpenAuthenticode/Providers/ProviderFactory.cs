using System;
using System.Collections.Generic;
using System.IO;

namespace OpenAuthenticode.Providers;

/// <summary>
/// Stores the registered providers and a factory method to create them.
/// </summary>
internal static class ProviderFactory
{
    private static readonly Dictionary<AuthenticodeProvider, Func<Stream, bool, AuthenticodeProviderBase>> _providers = [];

    private static readonly List<(AuthenticodeProvider, string[])> _providerExtensions = [];

    static ProviderFactory()
    {
        RegisterProvider(AuthenticodeProvider.PEBinary,
            PEBinaryProvider.FileExtensions,
            PEBinaryProvider.Create);
        RegisterProvider(AuthenticodeProvider.PowerShell,
            PowerShellScriptProvider.FileExtensions,
            PowerShellScriptProvider.Create);
        RegisterProvider(AuthenticodeProvider.PowerShellMof,
            PowerShellMofProvider.FileExtensions,
            PowerShellMofProvider.Create);
        RegisterProvider(AuthenticodeProvider.PowerShellXml,
            PowerShellXmlProvider.FileExtensions,
            PowerShellXmlProvider.Create);
        RegisterProvider(AuthenticodeProvider.Appx,
            AppxProvider.FileExtensions,
            AppxProvider.Create);
        RegisterProvider(AuthenticodeProvider.AppxBundle,
            AppxBundleProvider.FileExtensions,
            AppxBundleProvider.Create);
    }

    /// <summary>
    /// Get an instance of the provider requested.
    /// </summary>
    /// <param name="provider">The provider to create</param>
    /// <param name="stream">The stream containing the file data. Must be readable and seekable.</param>
    /// <param name="leaveOpen">Whether to leave the stream open when the provider is disposed</param>
    /// <param name="requireWrite">Whether the stream must also be writable (for signing operations)</param>
    /// <returns>The provider that can be used to get/set signatures</returns>
    public static AuthenticodeProviderBase Create(
        AuthenticodeProvider provider,
        Stream stream,
        bool leaveOpen = false,
        bool requireWrite = false)
    {
        ArgumentNullException.ThrowIfNull(stream, nameof(stream));
        ValidateStreamCapabilities(stream, requireWrite);

        if (!_providers.TryGetValue(provider, out var createFunc))
        {
            throw new NotImplementedException($"Authenticode support for '{provider}' has not been implemented");
        }

        return createFunc(stream, leaveOpen);
    }

    /// <summary>
    /// Get the provider for the extension provided.
    /// </summary>
    /// <remarks>
    /// Authenticode works on file extensions and will automatically select
    /// the provider based on the file extension in the
    /// <paramref name="extension"/> parameter.
    /// </remarks>
    /// <param name="extension">The extension (including the .) used to select the provider</param>
    /// <param name="stream">The stream containing the file data. Must be readable and seekable.</param>
    /// <param name="leaveOpen">Whether to leave the stream open when the provider is disposed</param>
    /// <param name="requireWrite">Whether the stream must also be writable (for signing operations)</param>
    /// <returns>The provider that can be used to get/set signatures</returns>
    public static AuthenticodeProviderBase Create(
        string extension,
        Stream stream,
        bool leaveOpen = false,
        bool requireWrite = false)
    {
        ArgumentNullException.ThrowIfNull(extension, nameof(extension));
        ArgumentNullException.ThrowIfNull(stream, nameof(stream));

        extension = extension.ToLowerInvariant();

        foreach ((var provider, var extensions) in _providerExtensions)
        {
            if (Array.Exists(extensions, e => e == extension))
            {
                return Create(provider, stream, leaveOpen, requireWrite);
            }
        }

        throw new NotImplementedException($"Authenticode support for '{extension}' has not been implemented");
    }

    private static void ValidateStreamCapabilities(Stream stream, bool requireWrite)
    {
        if (!stream.CanRead)
        {
            throw new ArgumentException("Stream must be readable", nameof(stream));
        }

        if (!stream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable", nameof(stream));
        }

        if (requireWrite && !stream.CanWrite)
        {
            throw new ArgumentException("Stream must be writable", nameof(stream));
        }
    }

    private static void RegisterProvider(AuthenticodeProvider provider, string[] extensions,
        Func<Stream, bool, AuthenticodeProviderBase> createFunc)
    {
        _providers.Add(provider, createFunc);
        _providerExtensions.Add((provider, extensions));
    }
}

/// <summary>
/// Identifiers for each known provider.
/// </summary>
public enum AuthenticodeProvider
{
    NotSpecified,
    PowerShell,
    PowerShellMof,
    PowerShellXml,
    PEBinary,
    Appx,
    AppxBundle,
}
