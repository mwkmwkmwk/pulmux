import asyncio
import socket
import collections


class DevConn:
    def __init__(self, mux, reader, writer):
        self.peerip, self.peerport = writer.get_extra_info('peername')
        print(f'new connection from {self.peerip}:{self.peerport}')
        self.mux = mux
        self.reader = reader
        self.writer = writer
        self.user = None
        self.completions = collections.deque()
        self.loop = asyncio.get_running_loop()
        self.dead = False
        self.wlock = asyncio.Lock()
        asyncio.create_task(self.handle_reader())
        asyncio.create_task(self.keepalive())

    async def error(self, exc):
        if self.dead:
            return
        self.dead = True
        self.writer.write(b'\x40')
        self.writer.close()
        for t, l, f in self.completions:
            f.set_exception(exc)
        self.completions.clear()
        self.mux.remove_dev_conn(self)
        if self.user is not None:
            await self.user.error(exc)

    async def keepalive(self):
        while True:
            if self.dead:
                break
            async with self.wlock:
                self.writer.write(b'\x41')
                await self.writer.drain()
            await asyncio.sleep(5)

    async def handle_reader(self):
        try:
            while True:
                c = await self.reader.readexactly(1)
                c = c[0]
                #print(f'RX {c:02x}')
                if c == 0x80:
                    cnt = await self.reader.readexactly(2)
                    cnt = int.from_bytes(cnt, 'little')
                    data = list(await self.reader.readexactly(cnt))
                    t, l, f = self.completions.popleft()
                    if t != 0x80 or l != cnt:
                        raise ValueError(t)
                    f.set_result(data)
                elif c == 0x80:
                    cnt = await self.reader.readexactly(2)
                    cnt = int.from_bytes(cnt, 'little')
                    data = await self.reader.readexactly(cnt * 2)
                    data = [
                        int.from_bytes(data[i*2:i*2+2], 'little')
                        for i in range(cnt)
                    ]
                    t, l, f = self.completions.popleft()
                    if t != 0x81 or l != cnt:
                        raise ValueError(t)
                    f.set_result(data)
                elif c == 0x82:
                    cnt = await self.reader.readexactly(2)
                    cnt = int.from_bytes(cnt, 'little')
                    data = await self.reader.readexactly(cnt * 4)
                    data = [
                        int.from_bytes(data[i*4:i*4+4], 'little')
                        for i in range(cnt)
                    ]
                    t, l, f = self.completions.popleft()
                    if t != 0x82 or l != cnt:
                        raise ValueError(t)
                    f.set_result(data)
                elif c in {0x90, 0x91, 0x92, 0x93, 0xa0, 0xa1, 0xb0}:
                    t, _, f = self.completions.popleft()
                    if t != c:
                        raise ValueError(t, c)
                    f.set_result(True)
                elif c == 0xe1:
                    t, _, f = self.completions.popleft()
                    if t != (c ^ 0x40):
                        raise ValueError(t)
                    f.set_result(False)
                elif c == 0xb1:
                    cnt = await self.reader.readexactly(2)
                    cnt = int.from_bytes(cnt, 'little')
                    data = await self.reader.readexactly(cnt * 2)
                    data = [
                        int.from_bytes(data[i*2:i*2+2], 'little')
                        for i in range(cnt)
                    ]
                    if self.user:
                        await self.user.got_uart_data(data)
                else:
                    raise ValueError(d)
        except Exception as e:
            print(f'reader crash on {self.peerip}:{self.peerport}: {e}')
            await self.error(e)

    async def rd8(self, addr, cnt):
        if cnt not in range(1 << 16):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x80, cnt, f))
        async with self.wlock:
            self.writer.write(b'\x00' + addr.to_bytes(4, 'little') + cnt.to_bytes(2, 'little'))
            await self.writer.drain()
        return f

    async def rd16(self, addr, cnt):
        if cnt not in range(1 << 16):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x81, cnt, f))
        async with self.wlock:
            self.writer.write(b'\x01' + addr.to_bytes(4, 'little') + cnt.to_bytes(2, 'little'))
            await self.writer.drain()
        return f

    async def rd32(self, addr, cnt):
        if cnt not in range(1 << 16):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x82, cnt, f))
        async with self.wlock:
            self.writer.write(b'\x02' + addr.to_bytes(4, 'little') + cnt.to_bytes(2, 'little'))
            await self.writer.drain()
        return f

    async def wr8(self, addr, data):
        if len(data) not in range(1 << 16):
            raise ValueError
        if any(x not in range(1 << 8) for x in data):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x90, None, f))
        async with self.wlock:
            self.writer.write(b'\x10' + addr.to_bytes(4, 'little') + len(data).to_bytes(2, 'little') + bytes(data))
            await self.writer.drain()
        return f

    async def wr16(self, addr, data):
        if len(data) not in range(1 << 16):
            raise ValueError
        if any(x not in range(1 << 16) for x in data):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x91, None, f))
        async with self.wlock:
            self.writer.write(b'\x11' + addr.to_bytes(4, 'little') + len(data).to_bytes(2, 'little') + b''.join(x.to_bytes(2, 'little') for x in data))
            await self.writer.drain()
        return f

    async def wr32(self, addr, data):
        if len(data) not in range(1 << 16):
            raise ValueError
        if any(x not in range(1 << 32) for x in data):
            raise ValueError
        if addr not in range(1 << 32):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x92, None, f))
        async with self.wlock:
            self.writer.write(b'\x12' + addr.to_bytes(4, 'little') + len(data).to_bytes(2, 'little') + b''.join(x.to_bytes(4, 'little') for x in data))
            await self.writer.drain()
        return f

    async def wrdevc(self, data):
        if len(data) not in range(1 << 16):
            raise ValueError
        if any(x not in range(1 << 32) for x in data):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0x93, None, f))
        async with self.wlock:
            self.writer.write(b'\x13' + len(data).to_bytes(2, 'little') + b''.join(x.to_bytes(4, 'little') for x in data))
            await self.writer.drain()
        return f

    async def fpga_reset(self):
        f = self.loop.create_future()
        self.completions.append((0xa0, None, f))
        async with self.wlock:
            self.writer.write(b'\x20')
            await self.writer.drain()
        return f

    async def fpga_boot(self):
        f = self.loop.create_future()
        self.completions.append((0xa1, None, f))
        async with self.wlock:
            self.writer.write(b'\x21')
            await self.writer.drain()
        return f

    async def uart_send(self, data):
        data = bytes(data)
        if len(data) not in range(1 << 16):
            raise ValueError
        f = self.loop.create_future()
        self.completions.append((0xb0, None, f))
        async with self.wlock:
            self.writer.write(b'\x30' + len(data).to_bytes(2, 'little') + data)
            await self.writer.drain()
        return f


class UserConn:
    def __init__(self, mux, reader, writer):
        self.peername = writer.get_extra_info('peername')
        print(f'new user connection from {self.peername}')
        self.mux = mux
        self.reader = reader
        self.writer = writer
        self.device = None
        #self.completions = collections.deque()
        self.loop = asyncio.get_running_loop()
        self.dev_future = self.loop.create_future()
        self.dead = False
        self.booted = False
        self.post_boot = b''
        self.wlock = asyncio.Lock()
        asyncio.create_task(self.handle_reader())

    async def error(self, exc):
        if self.dead:
            return
        self.dead = True
        s = str(exc).encode()
        self.writer.write(b'\x40' + len(s).to_bytes(2, 'little') + s)
        self.writer.close()
        self.mux.remove_user_conn(self)
        if self.device is not None:
            dev = self.device
            dev.user = None
            self.device = None
            await dev.error(exc)

    async def handle_reader(self):
        try:
            bslen = await self.reader.readexactly(4)
            bslen = int.from_bytes(bslen, 'little')
            if bslen % 4:
                raise ValueError(f'bitstream length {bslen} not divisible by 4')
            bs = await self.reader.readexactly(bslen)
            words = [
                int.from_bytes(bs[x:x+4], 'big')
                for x in range(0, bslen, 4)
            ]
            for x in range(min(len(words), 0x80)):
                if words[x] == 0xaa995566:
                    break
            else:
                raise ValueError(f'bitstream signature not found')
            device = await self.dev_future
            await device.fpga_reset()
            pos = 0
            while pos < bslen:
                cur = min(bslen - pos, 0x1000)
                await device.wrdevc(words[pos:pos+cur])
                pos += cur
            for x in range(0x80):
                f = await device.fpga_boot()
                result = await f
                if result:
                    print(f'{self.peername} booted {device.peerip} after {x} tries')
                    break
            else:
                raise Exception('FPGA failed to boot')
            async with self.wlock:
                self.writer.write(b'\xa1' + self.post_boot)
                self.booted = True
                self.post_boot = b''
                await self.writer.drain()
            while True:
                c = await self.reader.readexactly(1)
                c = c[0]
                if c == 0x30:
                    cnt = await self.reader.readexactly(4)
                    cnt = int.from_bytes(cnt, 'little')
                    while cnt:
                        cur = min(cnt, 0x1000)
                        data = await self.reader.readexactly(cur)
                        #print(f'USEND {data}')
                        await device.uart_send(data)
                        cnt -= cur
                else:
                    raise ValueError(f'unknown command')
        except Exception as e:
            if self.device:
                print(f'error on {self.device.peerip}:{self.device.peerport}: {e}')
            else:
                print(f'error on {self.peername}: {e}')
            await self.error(e)

    async def pair_with(self, dev):
        self.device = dev
        dev.user = self
        name = dev.peerip.encode()
        async with self.wlock:
            self.writer.write(b'\xa0' + len(name).to_bytes(2, 'little') + name)
            await self.writer.drain()
        self.dev_future.set_result(dev)

    async def got_uart_data(self, data):
        pkt = b''
        pos = 0
        dp = b''
        for d in data:
            if d in range(0x100):
                dp += bytes([d])
            else:
                if dp:
                    pkt += b'\xb1' + len(dp).to_bytes(2, 'little') + dp
                pkt += b'\xb2' + d.to_bytes(2, 'little')
        if dp:
            pkt += b'\xb1' + len(dp).to_bytes(2, 'little') + dp
        if not self.booted:
            self.post_boot += pkt
        else:
            async with self.wlock:
                self.writer.write(pkt)
                await self.writer.drain()


class DevMux:
    def __init__(self):
        self.device_connections = set()
        self.free_devices = set()
        self.waiting_users = set()
        self.user_connections = set()

    def remove_dev_conn(self, conn):
        self.device_connections.remove(conn)
        if conn in self.free_devices:
            self.free_devices.remove(conn)

    def remove_user_conn(self, conn):
        self.user_connections.remove(conn)
        if conn in self.waiting_users:
            self.waiting_users.remove(conn)

    async def handle_device_connection(self, reader, writer):
        conn = DevConn(self, reader, writer)
        self.device_connections.add(conn)
        await self.add_free_device(conn)

    async def handle_user_connection(self, reader, writer):
        conn = UserConn(self, reader, writer)
        self.user_connections.add(conn)
        if self.free_devices:
            dev = next(iter(self.free_devices))
            self.free_devices.remove(dev)
            await conn.pair_with(dev)
        else:
            self.waiting_users.add(conn)

    async def add_free_device(self, conn):
        if self.waiting_users:
            user = next(iter(self.waiting_users))
            self.waiting_users.remove(user)
            await user.pair_with(conn)
        else:
            self.free_devices.add(conn)

    async def run_user_server(self):
        srv = await asyncio.start_unix_server(self.handle_user_connection, '/run/muxsrv.sock', limit=0x1000000)
        async with srv:
            import os
            os.chmod('/run/muxsrv.sock', 0o666)
            await srv.serve_forever()

    async def main(self):
        asyncio.create_task(self.run_user_server())
        srv = await asyncio.start_server(self.handle_device_connection, '0.0.0.0', 666, limit=0x1000000, reuse_address=True)
        async with srv:
            await srv.serve_forever()

asyncio.run(DevMux().main())
