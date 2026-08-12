# pyjfl

An asynchronous Python client for **JFL Active** alarm panels: the frame codec and the TCP listener
those panels dial in to.

Written for, and extracted from, the [`jfl_alarm`](https://www.home-assistant.io/integrations/jfl_alarm)
Home Assistant integration — but it depends on nothing but the standard library and knows nothing
about Home Assistant, so it is usable from any asyncio program.

```bash
pip install pyjfl
```

## The topology is inverted

Nothing here dials a panel. **The panel dials out**, to the IP and port its installer programmed
into its reporting destination. So this is a *listener*, and one listener serves many panels at
once. A panel is identified by the serial in its `0x21` connection frame, never by its address: a
panel that comes back on a new DHCP lease is the same panel.

```python
import asyncio
from pyjfl import JflServer, PanelStatus

async def main() -> None:
    server = JflServer(host="0.0.0.0", port=9494)
    await server.async_start()

    link = server.link("0123456789")   # created on demand; outlives any one socket

    def on_packet(packet):
        if isinstance(packet, PanelStatus):
            print(packet.partitions, packet.zones)

    link.async_add_packet_listener(on_packet)

    while True:
        await asyncio.sleep(30)
        if link.connected:
            await link.async_request_status()   # the panel never pushes status

asyncio.run(main())
```

## What it covers

| | |
|---|---|
| **Frames** | Length-delimited reader that resynchronises rather than dying, checksum, sequence bytes |
| **Status** | Partitions, zones, PGM outputs, 32 trouble flags, the electric fence, mains and battery |
| **Events** | Contact ID classification, the panel's stored event buffer (`0x48`), 1073 records deep |
| **Control** | Arm / disarm / stay per partition, the electric fence, PGM outputs, zone bypass by bitmap |
| **Programming** | Reads the panel's whole configuration space (`0x44`): zone and partition names and types, users and their permissions, PGM functions, timers, holidays, schedules |
| **Wireless** | The radio inventory (`0x59`): detector model, firmware, signal quality, low battery |

Every mapping in it was recovered from packet captures against real hardware and from JFL's own
specification, and each is marked *confirmed* or *located but unconfirmed* in the source. Nothing is
guessed: a wrong label on a read is still a confident falsehood.

## Panels

| Model byte | Panel | Partitions | Zones | PGMs | Fence |
|---|---|---|---|---|---|
| `0xA0` | Active 32 Duo | 4 | 32 | 4 | yes |
| `0xA1` | Active 20 Ultra / 20 GPRS | 2 | 22 | 4 | yes |
| `0xA2` | Active 8 Ultra | 2 | 12 | 0 | no |
| `0xA3` | Active 20 Ethernet | 2 | 22 | 4 | yes |
| `0xA4` | Active 100 Bus | 16 | 99 | 16 | yes |
| `0xA5` | Active 20 Bus | 2 | 32 | 16 | yes |
| `0xA6` | Active Full 32 | 4 | 32 | 16 | no |
| `0xA7` | Active 20 | 2 | 32 | 4 | yes |
| `0xA8` | Active 8W | 2 | 32 | 4 | yes |
| `0x4B` | M-300+ | 0 | 0 | 4 | no |
| `0x5D` | M-300 Flex | 0 | 0 | 2 | no |

**Only the Active 32 Duo (firmware 7.60) has been validated against real hardware.** The rest are
implemented from the specification. An unknown model byte degrades to a permissive fallback and
never raises.

## ⚠️ This controls a real alarm system

- **Five wrong passwords lock remote access at the panel** until someone performs a valid keypad
  operation. There is no retry loop anywhere near the `0x37` authenticated command family, and you
  must not add one.
- Prefer the unauthenticated command path (`0x4E`/`0x4F`); it carries no lockout risk.
- Never write to programming addresses without a full backup. A window write replaces bytes it never
  displayed — that is how JFL's own ActiveNet erased a user's access code during the capture session
  this library was decoded from.
- The programming space holds user access codes in clear. `parse_users` reads them far enough to
  answer `has_code` and **discards them**, so nothing downstream can leak what it was never given.

## Credits

Author: Jonis Maurin Ceará. Based on the code developed by Carlos Jose Fernandes,
<https://github.com/fernac03/JFL_ACTIVE>.

## Licence

**GPL-3.0-only.** See [LICENSE](LICENSE).

In short, and without being legal advice: you may use, study, share and modify this library freely,
including commercially. If you distribute it, or anything derived from it, you must do so under the
same licence, with the source available and the attribution above intact. Modifications you
distribute have to be published — keeping an improved private fork to yourself and shipping it to
others is exactly what this licence forbids.

## Not affiliated with JFL

This is an independent, unofficial project by a private individual. It is **not affiliated with,
endorsed by, sponsored by or supported by JFL Equipamentos Eletrônicos Ltda.**, and carries no
warranty of any kind. "JFL", "Active" and "ActiveNet" are trademarks of their respective owners and
are used here only to identify the hardware this library talks to.

The protocol was recovered by observing traffic between the author's own panel and JFL's own
software, for interoperability. It controls a real alarm system: read the warnings above before
pointing it at one.
