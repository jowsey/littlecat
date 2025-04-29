using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Configuration;

[PacketHandler(ClientState.Configuration, (int)PacketIds.Serverbound.Configuration.KnownPacks)]
public class KnownPacks : IPacketHandler
{
    public Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got client's known packs.");
        var stream = client.GetStream();

        var packCount = stream.ReadVarInt();
        for (var i = 0; i < packCount; i++)
        {
            var packNamespace = stream.ReadString();
            var packId = stream.ReadString();
            var packVersion = stream.ReadString();
            Console.WriteLine($"Pack {i + 1}/{packCount}: {packNamespace}:{packId} v{packVersion}");
        }

        return Task.CompletedTask;
    }
}