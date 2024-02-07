namespace littlecat.Packets;

public class EncryptionResponsePacket(byte[] sharedSecret, byte[] verifyToken) : Packet(ServerboundPacketId.EncryptionResponse)
{
    public readonly byte[] SharedSecret = sharedSecret;
    public readonly byte[] VerifyToken = verifyToken;
}