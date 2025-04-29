using littlecat.Server;

namespace littlecat.Packets.Handlers.Login;

[PacketHandler(ClientState.Login, (int)PacketIds.Serverbound.Login.LoginAcknowledged)]
public class LoginAcknowledged : IPacketHandler
{
    public Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got login acknowledged.");
        client.ClientState = ClientState.Configuration;
        
        return Task.CompletedTask;
    }
}