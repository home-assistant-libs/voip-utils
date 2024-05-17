import asyncio
import logging

from .sip import CallPhoneDatagramProtocol, CALL_SRC_IP


async def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: CallPhoneDatagramProtocol(None),
        local_addr=(CALL_SRC_IP, 5060),
    )

    await protocol.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
