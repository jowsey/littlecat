using System.Numerics;
using System.Security.Cryptography;

namespace littlecat.Utils;

public static class StringUtils
{
    public static string ToMinecraftSha1HexDigest(this IEnumerable<byte> value)
    {
        var hash = SHA1.HashData(value.ToArray());
        Array.Reverse(hash); // reverse endianness
        var hashInt = new BigInteger(hash);
        return $"{(hashInt < 0 ? "-" : "")}{BigInteger.Abs(hashInt).ToString("X").ToLower().TrimStart("0")}";
    }
}