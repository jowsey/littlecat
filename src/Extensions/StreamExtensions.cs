using System.Text;

namespace littlecat.Extensions;

public static class StreamExtensions
{
    private const int SegmentBits = 0b01111111;
    private const int ContinueBit = 0b10000000;

    public const int MaxVarIntBytes = 5;
    public const int MaxVarLongBytes = 10;

    public static int ReadVarInt(this Stream stream)
    {
        var result = 0;
        var position = 0;

        while (true)
        {
            var currentByte = (byte)stream.ReadByte();
            result |= (currentByte & SegmentBits) << position;

            if ((currentByte & ContinueBit) == 0) break;

            position += 7;

            if (position >= 32) throw new InvalidDataException("VarInt is too big");
        }

        return result;
    }

    public static long ReadVarLong(this Stream stream)
    {
        var result = 0L;
        var position = 0;

        while (true)
        {
            var currentByte = (byte)stream.ReadByte();
            result |= (long)(currentByte & SegmentBits) << position;

            if ((currentByte & ContinueBit) == 0) break;

            position += 7;

            if (position >= 64) throw new InvalidDataException("VarLong is too big");
        }

        return result;
    }

    public static byte[] EncodeVarInt(int value)
    {
        var ms = new MemoryStream();

        while (true)
        {
            if ((value & ~SegmentBits) == 0)
            {
                ms.WriteByte((byte)value);
                return ms.ToArray();
            }

            ms.WriteByte((byte)((value & SegmentBits) | ContinueBit));
            value >>>= 7;
        }
    }

    public static byte[] EncodeVarLong(long value)
    {
        var ms = new MemoryStream();

        while (true)
        {
            if ((value & ~(long)SegmentBits) == 0)
            {
                ms.WriteByte((byte)value);
                return ms.ToArray();
            }

            ms.WriteByte((byte)((value & SegmentBits) | ContinueBit));
            value >>>= 7;
        }
    }

    // Read a length-prefixed string from the stream
    public static string ReadString(this Stream stream)
    {
        var buffer = new byte[stream.ReadVarInt()];
        _ = stream.Read(buffer, 0, buffer.Length);
        return Encoding.UTF8.GetString(buffer);
    }

    public static short ReadShort(this Stream stream)
    {
        return (short)ReadBigEndianBytes(stream, 2);
    }

    public static int ReadInt(this Stream stream)
    {
        return ReadBigEndianBytes(stream, 4);
    }

    public static long ReadLong(this Stream stream)
    {
        return ReadBigEndianBytes(stream, 8);
    }

    public static ulong ReadULong(this Stream stream)
    {
        return (ulong)ReadBigEndianBytes(stream, 8);
    }

    public static UInt128 ReadUuid(this Stream stream)
    {
        var mostSig64 = ReadULong(stream);
        var leastSig64 = ReadULong(stream);

        return new UInt128(mostSig64, leastSig64);
    }

    // Read a number of bytes from the stream in big-endian order
    public static int ReadBigEndianBytes(this Stream stream, int count)
    {
        var result = 0;
        for (var i = 0; i < count; i++)
        {
            result = (result << 8) | stream.ReadByte();
        }

        return result;
    }

    public static byte[] ReadLengthPrefixedBytes(this Stream stream)
    {
        var length = stream.ReadVarInt();
        var buffer = new byte[length];
        _ = stream.Read(buffer, 0, length);
        return buffer;
    }
    
    public static byte[] ReadExactly(this Stream stream, int count)
    {
        var buffer = new byte[count];
        _ = stream.Read(buffer, 0, count);
        return buffer;
    }
}