using littlecat.Utils;

namespace littlecat.Packets;

public class PacketBuilder
{
    private readonly MemoryStream _stream = new();

    public PacketBuilder(int id)
    {
        _stream.WriteVarInt(id);
    }

    public PacketBuilder AppendVarInt(int value)
    {
        _stream.WriteVarInt(value);
        return this;
    }

    public PacketBuilder AppendString(string value)
    {
        _stream.WriteString(value);
        return this;
    }

    public PacketBuilder AppendLong(long value)
    {
        _stream.WriteLong(value);
        return this;
    }

    public byte[] Build()
    {
        // todo if MemoryStreams introduce non-insignificant overhead we should probably just have a method to return the byte[] directly
        using var ms = new MemoryStream();
        ms.WriteLengthPrefixedBytes(_stream.ToArray());
        return ms.ToArray();
    }
}