using littlecat.Server;

namespace littlecat.Packets.Handlers;

public interface IPacketHandler
{ 
    Task HandlePacket(Server.Server server, MinecraftClient client);
}