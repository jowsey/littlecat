using System.Text;

namespace littlecat.Utils;

public static class StreamUtils
{
    private const int SEGMENT_BITS = 0b01111111;
    private const int CONTINUE_BIT = 0b10000000;

    public static int ReadVarInt(this Stream stream)
    {
        var value = 0;
        var position = 0;

        while (true)
        {
            var currentByte = (byte)stream.ReadByte();
            value |= (currentByte & SEGMENT_BITS) << position;
            if ((currentByte & CONTINUE_BIT) == 0) break;

            position += 7;

            if (position >= 32) throw new Exception("VarInt too big");
        }

        return value;
    }

    public static long ReadVarLong(this Stream stream)
    {
        var value = 0L;
        var position = 0;

        while (true)
        {
            var currentByte = (byte)stream.ReadByte();
            value |= (long)(currentByte & SEGMENT_BITS) << position;
            if ((currentByte & CONTINUE_BIT) == 0) break;

            position += 7;

            if (position >= 64) throw new Exception("VarLong too big");
        }

        return value;
    }

    public static void WriteVarInt(this Stream stream, int value)
    {
        while (true)
        {
            if ((value & ~SEGMENT_BITS) == 0)
            {
                stream.WriteByte((byte)value);
                return;
            }

            stream.WriteByte((byte)((value & SEGMENT_BITS) | CONTINUE_BIT));
            value >>>= 7;
        }
    }

    public static void WriteVarLong(this Stream stream, long value)
    {
        while (true)
        {
            if ((value & ~(long)SEGMENT_BITS) == 0)
            {
                stream.WriteByte((byte)value);
                return;
            }

            stream.WriteByte((byte)((value & SEGMENT_BITS) | CONTINUE_BIT));
            value >>>= 7;
        }
    }

    public static byte[] ReadLengthPrefixedBytes(this Stream stream)
    {
        var length = stream.ReadVarInt();
        var bytes = new byte[length];
        stream.ReadExactly(bytes, 0, length);
        return bytes;
    }

    public static void WriteLengthPrefixedBytes(this Stream stream, byte[] bytes)
    {
        stream.WriteVarInt(bytes.Length);
        stream.Write(bytes);
    }

    private static byte[] ReadBigEndianBytes(this Stream stream, int length)
    {
        var bytes = new byte[length];
        stream.ReadExactly(bytes, 0, length);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }

    private static void WriteBigEndianBytes(this Stream stream, byte[] bytes)
    {
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        stream.Write(bytes);
    }

    public static string ReadString(this Stream stream) => Encoding.UTF8.GetString(stream.ReadLengthPrefixedBytes());
    public static void WriteString(this Stream stream, string value) => stream.WriteLengthPrefixedBytes(Encoding.UTF8.GetBytes(value));

    public static ushort ReadUShort(this Stream stream) => BitConverter.ToUInt16(ReadBigEndianBytes(stream, 2), 0);
    public static void WriteUShort(this Stream stream, ushort value) => stream.WriteBigEndianBytes(BitConverter.GetBytes(value));

    public static long ReadLong(this Stream stream) => BitConverter.ToInt64(ReadBigEndianBytes(stream, 8), 0);
    public static void WriteLong(this Stream stream, long value) => stream.WriteBigEndianBytes(BitConverter.GetBytes(value));
}