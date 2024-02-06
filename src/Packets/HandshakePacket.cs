namespace littlecat.Packets;

public class HandshakePacket(int protocolVersion, string serverAddress, int serverPort, int nextState) : Packet(ServerboundPacketId.Handshake) 
{
    public readonly int ProtocolVersion = protocolVersion;
    public readonly string ServerAddress = serverAddress;
    public readonly int ServerPort = serverPort;
    public readonly int NextState = nextState;
}