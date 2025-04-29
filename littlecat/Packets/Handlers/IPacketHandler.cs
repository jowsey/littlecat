using littlecat.Server;

namespace littlecat.Packets.Handlers;

public interface IPacketHandler
{
    Task HandlePacket(PacketInfo packet, Server.Server server, MinecraftClient client);
}