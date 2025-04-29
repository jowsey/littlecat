using littlecat.Utils;

namespace littlecat.Packets;

public static class PacketIds
{
    public static class Serverbound
    {
        public enum Handshake
        {
            Handshake = 0x00
        }

        public enum Status
        {
            StatusRequest = 0x00,
            PingRequest = 0x01
        }

        public enum Login
        {
            LoginStart = 0x00,
            EncryptionResponse = 0x01,
            LoginAcknowledged = 0x03
        }

        public enum Configuration
        {
            ClientInformation = 0x00,
            PluginMessage = 0x02,
            KnownPacks = 0x07
        }
    }

    public static class Clientbound
    {
        public enum Status
        {
            StatusResponse = 0x00,
            PongResponse = 0x01
        }

        public enum Login
        {
            EncryptionRequest = 0x01,
            LoginSuccess = 0x02
        }

        public enum Configuration
        {
            PluginMessage = 0x01,
            FeatureFlags = 0x0C,
            KnownPacks = 0x0E,
        }
    }
}

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

    public PacketBuilder AppendBytes(byte[] bytes)
    {
        _stream.Write(bytes);
        return this;
    }

    public PacketBuilder AppendLengthPrefixedBytes(byte[] bytes)
    {
        _stream.WriteLengthPrefixedBytes(bytes);
        return this;
    }

    public PacketBuilder AppendBoolean(bool value)
    {
        _stream.WriteBoolean(value);
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

    public PacketBuilder AppendUuid(UInt128 value)
    {
        _stream.WriteUuid(value);
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