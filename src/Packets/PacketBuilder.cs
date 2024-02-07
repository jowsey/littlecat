using System.Text;
using littlecat.Extensions;
using littlecat.Utils;

namespace littlecat.Packets;

// builder api

public class PacketBuilder(ClientboundPacketId id)
{
    private ClientboundPacketId _id = id;
    private MemoryStream _dataStream = new();

    public PacketBuilder AppendVarInt(int value)
    {
        var varInt = StreamExtensions.EncodeVarInt(value);
        _dataStream.Write(varInt, 0, varInt.Length);
        return this;
    }

    public PacketBuilder AppendVarLong(long value)
    {
        var varLong = StreamExtensions.EncodeVarLong(value);
        _dataStream.Write(varLong, 0, varLong.Length);
        return this;
    }

    public PacketBuilder AppendLengthPrefixedBytes(byte[] value)
    {
        AppendVarInt(value.Length);
        _dataStream.Write(value, 0, value.Length);
        return this;
    }

    public PacketBuilder AppendString(string value)
    {
        AppendVarInt(value.Length);
        _dataStream.Write(Encoding.UTF8.GetBytes(value), 0, value.Length);
        return this;
    }
    
    public PacketBuilder AppendLong(long value)
    {
        var longBytes = BitConverter.GetBytes(value).Reverse().ToArray();
        _dataStream.Write(value.ToBigEndianBytes(), 0, longBytes.Length);
        return this;
    }
    
    public PacketBuilder AppendInt(int value)
    {
        var intBytes = BitConverter.GetBytes(value).Reverse().ToArray();
        _dataStream.Write(value.ToBigEndianBytes(), 0, intBytes.Length);
        return this;
    }
    
    public PacketBuilder AppendShort(short value)
    {
        var shortBytes = BitConverter.GetBytes(value).Reverse().ToArray();
        _dataStream.Write(value.ToBigEndianBytes(), 0, shortBytes.Length);
        return this;
    }

    public byte[] GetBytes()
    {
        var packetId = StreamExtensions.EncodeVarInt((int)_id);
        var packetData = _dataStream.ToArray();
        
        var totalPacketLength = StreamExtensions.EncodeVarInt(packetId.Length + packetData.Length);

        var packet = new byte[totalPacketLength.Length + packetId.Length + packetData.Length];
        totalPacketLength.CopyTo(packet, 0);
        packetId.CopyTo(packet, totalPacketLength.Length);
        packetData.CopyTo(packet, totalPacketLength.Length + packetId.Length);
        
        return packet;
    }
    
    public static implicit operator ReadOnlySpan<byte>(PacketBuilder builder) => builder.GetBytes();
}