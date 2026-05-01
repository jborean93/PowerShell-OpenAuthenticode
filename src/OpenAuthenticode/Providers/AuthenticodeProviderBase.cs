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
    /// <param name="hasher">The hashing object to append data to</param>
    /// <param name="offset">The offset in the stream to start reading from</param>
    /// <param name="length">The number of bytes to read and hash</param>
    /// <param name="buffer">A buffer to use for reading data</param>
    protected void HashStreamRange(
        IncrementalHash hasher,
        long offset,
        long length,
        Span<byte> buffer)
    {
        if (length <= 0)
        {
            return;
        }

        Stream.Position = offset;

        long remaining = length;
        while (remaining > 0)
        {
            // As buffer.Length is an int we can be sure the result will fit
            // into an int.
            int toRead = (int)Math.Min(remaining, buffer.Length);
            int bytesRead = Stream.Read(buffer[..toRead]);
            if (bytesRead == 0)
            {
                break;
            }

            hasher.AppendData(buffer[..bytesRead]);
            remaining -= bytesRead;
        }
    }

    /// <summary>
    /// Hashes a stream range while excluding a specific section.
    /// </summary>
    /// <param name="hasher">The hashing object to append data to</param>
    /// <param name="rangeOffset">The starting offset of the range to hash</param>
    /// <param name="rangeLength">The total length of the range to hash</param>
    /// <param name="excludeOffset">The offset of the section to exclude (absolute, not relative)</param>
    /// <param name="excludeLength">The length of the section to exclude</param>
    /// <param name="buffer">A buffer to use for reading data</param>
    protected void HashStreamRangeWithExclusion(
        IncrementalHash hasher,
        long rangeOffset,
        long rangeLength,
        long excludeOffset,
        long excludeLength,
        Span<byte> buffer)
    {
        long rangeEnd = rangeOffset + rangeLength;
        long excludeEnd = excludeOffset + excludeLength;

        // If exclusion is at the start of the range
        if (excludeOffset == rangeOffset)
        {
            // Hash after exclusion (if there's anything after)
            if (excludeEnd < rangeEnd)
            {
                HashStreamRange(hasher, excludeEnd, rangeEnd - excludeEnd, buffer);
            }
        }
        else
        {
            // Hash before exclusion
            if (excludeOffset > rangeOffset)
            {
                HashStreamRange(hasher, rangeOffset, excludeOffset - rangeOffset, buffer);
            }

            // Hash after exclusion (if there's anything after)
            if (excludeEnd < rangeEnd)
            {
                HashStreamRange(hasher, excludeEnd, rangeEnd - excludeEnd, buffer);
            }
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
