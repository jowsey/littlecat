using System.Numerics;
using System.Security.Cryptography;

namespace littlecat.Extensions;

public static class StringExtensions
{
    public static string ToMinecraftShaHexDigest(this IEnumerable<byte> input)
    {
        var hash = SHA1.HashData(input.ToArray());
        // convert to big-endian
        Array.Reverse(hash);

        var b = new BigInteger(hash);

        // format as hex and trim leading 0s; if negative, make absolute and add minus to string
        return (b < 0 ? "-" + (-b).ToString("x") : b.ToString("x")).TrimStart('0');
    }
}