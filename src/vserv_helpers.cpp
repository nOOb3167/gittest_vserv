#include <cstdlib>
#include <cstring>

#include <gittest/vserv_helpers.h>

/** needs to be destructible by regular free(2) (ex gs_vserv_write_elt_del_sp_free) */
int gs_packet_copy_create(struct GsPacket *Packet, uint8_t **oABuf, size_t *oLenA)
{
	uint8_t *ABuf = NULL;
	size_t LenA = Packet->dataLength;
	if (!(ABuf = (uint8_t *)malloc(LenA)))
		return 1;
	memcpy(ABuf, Packet->data, Packet->dataLength);
	if (oABuf)
		*oABuf = ABuf;
	if (oLenA)
		*oLenA = LenA;
	return 0;
}

int gs_packet_space(struct GsPacket *Packet, size_t Offset, size_t SpaceRequired)
{
	return Offset + SpaceRequired > Packet->dataLength;
}

uint8_t gs_read_byte(uint8_t *Ptr)
{
	return Ptr[0];
}

uint16_t gs_read_short(uint8_t *Ptr)
{
	uint16_t r = 0;
	r |= (Ptr[0] & 0xFF) << 0;
	r |= (Ptr[1] & 0xFF) << 8;
	return r;
}

uint32_t gs_read_uint(uint8_t *Ptr)
{
	uint32_t r = 0;
	r |= (Ptr[0] & 0xFF) << 0;
	r |= (Ptr[1] & 0xFF) << 8;
	r |= (Ptr[2] & 0xFF) << 16;
	r |= (Ptr[3] & 0xFF) << 24;
	return r;
}

void gs_write_byte(uint8_t *Ptr, uint8_t Byte)
{
	Ptr[0] = Byte;
}

void gs_write_short(uint8_t *Ptr, uint16_t UShort)
{
	Ptr[0] = (UShort & 0xFF);
	Ptr[1] = ((UShort >> 8) & 0xFF);
}

void gs_write_uint(uint8_t *Ptr, uint32_t UInt)
{
	Ptr[0] = (UInt & 0xFF);
	Ptr[1] = ((UInt >> 8) & 0xFF);
	Ptr[2] = ((UInt >> 16) & 0xFF);
	Ptr[3] = ((UInt >> 24) & 0xFF);
}
