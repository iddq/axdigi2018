# axdigi2018

AX.25 packet radio digipeater for linux

## Features

- cross port digipeating
- aprs digipeater interworking
- periodical beacons

## Building

To build `axdigi2018`:

```
make
```

To run with default options:

```
./axdigi2018
```

## Options

- `--enable-beacon`, `-b` -- enable a periodic beacon every `--beacon-interval` seconds
- `--beacon-text`, `-t` *text* -- set beacon text
- `--beacon-dest`, `-d` *callsign* -- set beacon destination
- `--beacon-interval`, `-i` *seconds* -- set beacon interval (default 300)
- `--beacon-path`, `-p` *digi1,digi2,...* -- set beacon path
