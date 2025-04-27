using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Status;

[PacketHandler(ClientState.Status, (int)PacketIds.Serverbound.Status.PingRequest)]
public class PingRequest : IPacketHandler
{
    public void HandlePacket(Server.Server server, MinecraftClient client)
    {
        var stream = client.GetStream();
        var timestamp = stream.ReadLong();

        var packet = new PacketBuilder((int)PacketIds.Clientbound.Status.PongResponse)
            .AppendLong(timestamp);

        stream.Write(packet.Build());
    }
}