using littlecat.Server;

namespace littlecat.Packets.Handlers;

public interface IPacketHandler
{
    void HandlePacket(Server.Server server, MinecraftClient client);
}