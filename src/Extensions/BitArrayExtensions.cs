using System.Collections;

namespace littlecat.Extensions;

public static class BitArrayExtensions
{
    public static long[] ToLongArray(this BitArray bits)
    {
        var longs = new long[(bits.Length + 63) / 64];
        bits.CopyTo(longs, 0);
        return longs;
    }
}