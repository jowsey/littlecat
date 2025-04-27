using littlecat.Server;

namespace littlecat.Packets.Handlers;

[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public class PacketHandlerAttribute(ClientState clientState, int packetId) : Attribute
{
    public ClientState ClientState { get; } = clientState;
    public int PacketId { get; } = packetId;
}