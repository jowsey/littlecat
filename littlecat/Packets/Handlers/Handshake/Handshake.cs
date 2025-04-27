using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Handshake;

[PacketHandler(ClientState.Handshake, (int)PacketIds.Serverbound.Handshake.Handshake)]
public class Handshake : IPacketHandler
{
    public void HandlePacket(Server.Server server, MinecraftClient client)
    {
        var stream = client.GetStream();
        
        var protocolVersion = stream.ReadVarInt();
        var serverAddress = stream.ReadString();
        var serverPort = stream.ReadUShort();
        var nextState = stream.ReadVarInt();

        Console.WriteLine($"Protocol: {protocolVersion}");
        Console.WriteLine($"Server address: {serverAddress}");
        Console.WriteLine($"Server port: {serverPort}");
        Console.WriteLine($"Next state: {nextState}");

        client.ClientState = nextState switch
        {
            1 => ClientState.Status,
            2 => ClientState.Login,
            3 => ClientState.Transfer,
            _ => throw new Exception($"Invalid next state {nextState} from handshake")
        };
    }
}