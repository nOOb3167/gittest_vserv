#ifndef _VSERV_HELPERS_H_
#define _VSERV_HELPERS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER
#  include <malloc.h>  // alloca
#else
#  include <alloca.h>
#endif

#define GS_48KHZ 48000

#define GS_NOALERR() do { GS_ASSERT(AL_NO_ERROR == alGetError()); } while(0)

#define GS_ALLOCA_VAR(VARNAME, TT, NELT) TT *VARNAME = (TT *) alloca(sizeof (TT) * (NELT))
#define GS_ALLOCA_ASSIGN(VARNAME, TT, NELT) (VARNAME) = ((TT *) alloca(sizeof (TT) * (NELT)))

struct GsPacket
{
	uint8_t *data;
	size_t   dataLength;
};

int gs_packet_copy_create(struct GsPacket *Packet, uint8_t **oABuf, size_t *oLenA);
int gs_packet_space(struct GsPacket *Packet, size_t Offset, size_t SpaceRequired);

uint8_t gs_read_byte(uint8_t *Ptr);
uint16_t gs_read_short(uint8_t *Ptr);
uint32_t gs_read_uint(uint8_t *Ptr);
void gs_write_byte(uint8_t *Ptr, uint8_t Byte);
void gs_write_short(uint8_t *Ptr, uint16_t UShort);
void gs_write_uint(uint8_t *Ptr, uint32_t UInt);

#endif /* _VSERV_HELPERS_H_ */
