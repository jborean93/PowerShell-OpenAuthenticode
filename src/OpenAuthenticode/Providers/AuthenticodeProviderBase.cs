using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;

namespace OpenAuthenticode.Providers;

/// <summary>
/// Base class for authenticode providers that manage file streams and signatures.
/// </summary>
internal abstract class AuthenticodeProviderBase : IDisposable
{
    private const int BufferSize = 8192;
    private readonly Stream _stream;
    private readonly bool _leaveOpen;

    /// <summary>
    /// The provider enum identifier.
    /// </summary>
    public abstract AuthenticodeProvider Provider { get; }

    /// <summary>
    /// Gets and sets the PKCS #7 signature data.
    /// An empty byte[] is treated as having no signature.
    /// </summary>
    public byte[] Signature { get; set; } = [];

    /// <summary>
    /// The stream containing the file data.
    /// </summary>
    protected Stream Stream => _stream;

    protected AuthenticodeProviderBase(Stream stream, bool leaveOpen)
    {
        _stream = stream;
        _leaveOpen = leaveOpen;
    }

    /// <summary>
    /// Hash a range of data from the stream using a pooled buffer.
    /// </summary>
    /// <param name="algo">The hash algorithm to append data to</param>
    /// <param name="offset">The offset in the stream to start reading from</param>
    /// <param name="length">The number of bytes to read and hash</param>
    protected void HashStreamRange(IncrementalHash algo, long offset, int length)
    {
        if (length <= 0)
        {
            return;
        }

        Stream.Position = offset;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            int remaining = length;
            while (remaining > 0)
            {
                int toRead = Math.Min(remaining, BufferSize);
                int bytesRead = Stream.Read(buffer, 0, toRead);
                if (bytesRead == 0)
                {
                    break;
                }

                algo.AppendData(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Gets the hashed data contents for the file which is then signed.
    /// </summary>
    /// <remarks>
    /// It is up to the provider implementation to set the indirect data
    /// content as needed. The data content is then placed in the SignedCms
    /// object and signed with the certificate provided.
    /// </remarks>
    /// <param name="digestAlgorithm">The digest/hash algorithm to use</param>
    /// <returns>The indirect data content to sign</returns>
    public abstract SpcIndirectData HashData(Oid digestAlgorithm);

    /// <summary>
    /// Gets extra attributes that need to be included in the data to be
    /// signed in the PKCS #7 signature. It is up to the provider to add any
    /// provider specific attributes.
    /// </summary>
    /// <returns>The ASN encoded attributes to be included as signed attributes.</returns>
    public virtual AsnEncodedData[] GetAttributesToSign() => [];

    /// <summary>
    /// Saves the file contents and signature (if present) to the owned stream.
    /// The stream must be writable and seekable.
    /// </summary>
    public abstract void Save();

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _stream?.Dispose();
        }
    }
}
