namespace littlecat.Packets;

public enum ServerboundPacketId
{
    Handshake = 0x00,
    StatusRequest = 0x00,
    LoginStart = 0x00,
    PingRequest = 0x01,
    EncryptionResponse = 0x01,
    LoginAcknowledged = 0x03
}

public enum ClientboundPacketId
{
    StatusResponse = 0x00,
    PongResponse = 0x01,
    EncryptionRequest = 0x01,
    LoginSuccess = 0x02,
}

public abstract class Packet(ServerboundPacketId id)
{
    public readonly ServerboundPacketId Id = id;
}