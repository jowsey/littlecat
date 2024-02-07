using System.Numerics;
using System.Security.Cryptography;

namespace littlecat.Extensions;

public static class StringExtensions
{
    public static string ToMinecraftShaHexDigest(this IEnumerable<byte> input) 
    {
        // based on https://gist.github.com/ammaraskar/7b4a3f73bee9dc4136539644a0f27e63
        
        var hash = SHA1.HashData(input.ToArray());
        // make big endian
        Array.Reverse(hash);
        
        var b = new BigInteger(hash);
        
        // add - if necessary, format as hex and trim leading 0s
        return (b < 0 ? "-" : "") + b.ToString("x").TrimStart('0');
    }
}