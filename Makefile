all:
	$(CC) -DDO_NOT_FORWARD_APRS_PACKET -Wall -g -oaxdigi2018 axdigi2018.c hexdump.c
