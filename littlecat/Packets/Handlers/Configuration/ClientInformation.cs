using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Configuration;

[PacketHandler(ClientState.Configuration, (int)PacketIds.Serverbound.Configuration.ClientInformation)]
public class ClientInformation : IPacketHandler
{
    public Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got client information.");
        var stream = client.GetStream();
        
        var locale = stream.ReadString();
        var viewDistance = stream.ReadSByte();
        var chatMode = stream.ReadVarInt();
        var chatColors = stream.ReadBoolean();
        var displayedSkinParts = stream.ReadByte();
        var mainHand = stream.ReadVarInt();
        var enableTextFiltering = stream.ReadBoolean();
        var enableServerListing = stream.ReadBoolean();
        var particleStatus = stream.ReadVarInt();
        
        Console.WriteLine($"Locale: {locale}");
        Console.WriteLine($"View distance: {viewDistance}");
        Console.WriteLine($"Chat mode: {chatMode}");
        Console.WriteLine($"Chat colors: {chatColors}");
        Console.WriteLine($"Displayed skin parts: {displayedSkinParts}");
        Console.WriteLine($"Main hand: {mainHand}");
        Console.WriteLine($"Enable text filtering: {enableTextFiltering}");
        Console.WriteLine($"Enable server listing: {enableServerListing}");
        Console.WriteLine($"Particle status: {particleStatus}");

        return Task.CompletedTask;
    }
}