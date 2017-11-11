#include <cstring>

#include <vector>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_net.h>

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
};

struct GsVServCtlCb1
{
	struct GsVServCtlCb base;
	struct GsVServConExt *Ext; /*owned*/
};

int gs_vserv_crank0(struct GsVServCtlCb *Cb, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	GS_LOG(I, PF, "pkt [%d]", (int)Packet->dataLength);

	char *Data = (char *)malloc(5);
	size_t Size = 5;

	memcpy(Data, "HELLO", 5);

	if (!!(r = gs_vserv_respond_enqueue(
		Respond,
		gs_vserv_write_elt_del_free, gs_vserv_write_elt_del_sp_free,
		&Data, &Size, Addr, 1)))
	{
		GS_GOTO_CLEAN();
	}

clean:

	return r;
}

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::vector<int> ServFd;
	struct GsVServConExt *Ext = NULL;
	struct GsVServCtlCb1 *Cb1 = NULL;
	struct GsVServCtl *ServCtl = NULL;

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;
	Cb1 = new GsVServCtlCb1();
	Cb1->base.CbCrank = gs_vserv_crank0;
	Cb1->Ext = GS_ARGOWN(&Ext);

	ServFd.resize(1, -1);

	if (!!(r = gs_vserv_sockets_create(std::to_string(CommonVars->VServPort).c_str(), ServFd.data(), ServFd.size())))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_start_2(ServFd.data(), ServFd.size(), &Cb1->base, &ServCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_quit_wait(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ext, struct GsVServConExt);
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		gs_close_cond(&ServFd[i]);

	return r;
}
