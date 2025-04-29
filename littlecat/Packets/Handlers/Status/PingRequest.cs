using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Status;

[PacketHandler(ClientState.Status, (int)PacketIds.Serverbound.Status.PingRequest)]
public class PingRequest : IPacketHandler
{
    public Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got ping request.");

        var stream = client.GetStream();
        var timestamp = stream.ReadLong();

        var pongResponsePacket = new PacketBuilder((int)PacketIds.Clientbound.Status.PongResponse).AppendLong(timestamp);
        stream.Write(pongResponsePacket.Build());
        
        Console.WriteLine("Sent ping response.");

        client.Dispose(); // status ping sequence finished
        return Task.CompletedTask;
    }
}