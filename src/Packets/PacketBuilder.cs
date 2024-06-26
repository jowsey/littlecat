﻿using System.Text;
using littlecat.Extensions;
using littlecat.Utils;
using SharpNBT;

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
        var lower = (ulong)value; //next .NET feature release (8.1/9) should get BitCoverter for UInt128
        var upper = (ulong)(value >> 64);
        
        AppendUlong(upper);
        AppendUlong(lower);
        
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