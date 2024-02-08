namespace littlecat.Packets;

public enum ServerboundPacketId //todo might not use this anymore maybe remove
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
    PluginMessage = 0x00,
    PongResponse = 0x01,
    EncryptionRequest = 0x01,
    LoginSuccess = 0x02,
    FinishConfiguration = 0x02,
    RegistryData = 0x05,
    ChangeDifficulty = 0x0B,
    Play = 0x29
}