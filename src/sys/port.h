#pragma once


NTSTATUS	InitPortComm(PWCHAR port_name, PFLT_FILTER filter);
void		UnInitPortComm();
