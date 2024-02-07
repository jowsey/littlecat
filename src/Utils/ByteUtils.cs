namespace littlecat.Utils;

public static class ByteUtils
{
    public static byte[] ToBigEndianBytes(this short value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }
    
    public static byte[] ToBigEndianBytes(this int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }

    public static byte[] ToBigEndianBytes(this long value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }
    
    public static byte[] ToBigEndianBytes(this ulong value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }
}