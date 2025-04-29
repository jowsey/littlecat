using System.Text;
using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Configuration;

[PacketHandler(ClientState.Configuration, (int)PacketIds.Serverbound.Configuration.PluginMessage)]
public class PluginMessage : IPacketHandler
{
    public Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got plugin message.");
        var stream = client.GetStream();
        var channel = stream.ReadString(out var channelLength);

        var dataLength = packet.DataLength - channelLength;
        
        var data = new byte[dataLength];
        stream.ReadExactly(data, 0, dataLength);

        Console.WriteLine($"Got plugin message on channel {channel}: {Encoding.UTF8.GetString(data)}");
        return Task.CompletedTask;
    }
}