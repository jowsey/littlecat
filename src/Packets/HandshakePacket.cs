namespace littlecat.Packets;

public enum HandshakeNextState
{
    Status = 1,
    Login = 2
}

public class HandshakePacket(int protocolVersion, string serverAddress, int serverPort, HandshakeNextState nextState) : Packet(ServerboundPacketId.Handshake) 
{
    public readonly int ProtocolVersion = protocolVersion;
    public readonly string ServerAddress = serverAddress;
    public readonly int ServerPort = serverPort;
    public readonly HandshakeNextState NextState = nextState;
}