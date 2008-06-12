/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 * <NEED TO FIX KEYWORDS>
 */


#ifndef	__daemon_utils_h__
#define	__daemon_utils_h__

#ifdef __cplusplus
extern "C"
{
#endif

#define FIFONAME_MAX_BUFSIZE    256        // Max name length for launcher fifos

/*
 * Protocol used over fifos
 */
#define FIFO_FD_ACK     "FD OK"
#define FIFO_PING_CMD   "PING"
#define FIFO_EXIT_CMD   "EXIT"
#define INSTANCE_DIED_TOKEN   "DIED"

#define PID_ASCII_SIZE 11

int  SendClientFd(int, int, int, int);
int  ReceiveClientFd(int, int,  int *, int);
void SetupSignalHandlers(void (*fp)(int), int);
int  DoFifoReceive(int, void *,int, int);
void DeletePidFile(int);
int  GetPidFromFile(int);
int  DoFifoCmd(int, char *);
int  OpenFifo(char *, int);
int  PingFifo(int, int, int);
int  SendMsg(int, char *);
int  SendCmd(int, char *);
int  StopInstance(int, int);
/*
 * Status codes
 */
#define SUCCESS         0
#define ERROR          -1
#define TIMEOUT        -2
#define INTERRUPTED    -3
#define SEVERE         -4
#define TERMINATED     -5
#define INSTANCE_DIED  -6

#ifdef __cplusplus
extern "C"
}
#endif

#endif
