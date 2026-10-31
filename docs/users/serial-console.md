# Serial and VGA consoles

For implementation and testing, see the [developer guide](../dev/serial-console.md).

The amd64 image uses the first standard firmware serial port (`ttyS0`, GRUB unit 0)
at **115200 baud, 8 data bits, no parity, 1 stop bit**, with no flow control. Connect
a VT100-compatible terminal at those settings. VGA and keyboard remain available.
This selects a conventional port, not a hardcoded I/O address or IRQ; firmware/BMC
serial redirection must expose the matching port. Platforms exposing only a different
UART need a corresponding boot-console selection. Arbitrary USB serial devices on
the router are not firmware boot consoles.

Serial and VGA require a username and password. The fresh image's account is
`nvyr`, password `nvyr`; automatic login is disabled. Successful login starts the
CLI, just as in SSH. See [users and roles](login.md). Prompts, Tab/`?` completion,
history, configuration mode and terminal restoration use the existing CLI. Serial
sessions default to `TERM=vt100`; VGA sessions retain their Linux terminal type.
