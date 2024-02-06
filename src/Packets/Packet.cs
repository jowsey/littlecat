namespace littlecat.Packets;

public enum ServerboundPacketId
{
    Handshake = 0x00,
    PingRequest = 0x01
}

public enum ClientboundPacketId
{
    StatusResponse = 0x00,
    PongResponse = 0x01
}

public abstract class Packet(ServerboundPacketId id)
{
    public readonly ServerboundPacketId Id = id;
}