namespace littlecat.Packets;

public class PingRequestPacket(long payload) : Packet(ServerboundPacketId.PingRequest)
{
    public readonly long Payload = payload;
}