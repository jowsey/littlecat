using System.Collections;
using System.Net.Http.Headers;
using System.Text;
using littlecat.Extensions;
using littlecat.Utils;
using SharpNBT;

namespace littlecat.Packets;

public class PacketBuilder(ClientboundPacketId id)
{
    public readonly ClientboundPacketId Id = id;
    private readonly MemoryStream _dataStream = new();

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

    public PacketBuilder AppendLengthPrefixedByteArray(byte[] value)
    {
        AppendVarInt(value.Length);
        _dataStream.Write(value, 0, value.Length);
        return this;
    }
    
    public PacketBuilder AppendBytes(byte[] value)
    {
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
        var longBytes = value.ToBigEndianBytes();
        _dataStream.Write(longBytes, 0, longBytes.Length);
        return this;
    }
    
    public PacketBuilder AppendUlong(ulong value)
    {
        var ulongBytes = value.ToBigEndianBytes();
        _dataStream.Write(ulongBytes, 0, ulongBytes.Length);
        return this;
    }
    
    public PacketBuilder AppendUuid(UInt128 value)
    {
        var uint128Bytes = value.ToBigEndianBytes();
        _dataStream.Write(uint128Bytes, 0, uint128Bytes.Length); // todo make sure this works otherwise do what we did before
        return this;
    }
    
    public PacketBuilder AppendBoolean(bool value)
    {
        _dataStream.WriteByte(value ? (byte)1 : (byte)0);
        return this;
    }
    
    public PacketBuilder AppendInt(int value)
    {
        var intBytes = value.ToBigEndianBytes();
        _dataStream.Write(intBytes, 0, intBytes.Length);
        return this;
    }
    
    public PacketBuilder AppendByte(byte value)
    {
        _dataStream.WriteByte(value);
        return this;
    }
    
    public PacketBuilder AppendSByte(sbyte value)
    {
        _dataStream.WriteByte((byte)value);
        return this;
    }
    
    public PacketBuilder AppendNbt(CompoundTag value)
    {
        using var writer = new TagWriter(_dataStream, FormatOptions.Java);
        writer.WriteTag(value);
        return this;
    }
    
    // C# BitArray <-> Java BitSet
    public PacketBuilder AppendBitSet(BitArray value)
    {
        var longs = value.ToLongArray();
        AppendVarInt(longs.Length);
        foreach (var l in longs)
        {
            AppendLong(l);
        }
        return this;
    }

    public byte[] GetBytes()
    {
        var packetId = StreamExtensions.EncodeVarInt((int)Id);
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