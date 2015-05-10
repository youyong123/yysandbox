#pragma once


NTSTATUS	init_lpc(PWCHAR port_name, PFLT_FILTER filter);
void		uninit_lpc();
