#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: eph

import re
import sys
import argparse
import threading
from struct import pack, unpack

try:
    from queue import Queue  # Python 3
except ImportError:
    from Queue import Queue  # Python 2

from pipeapp import Application, monotonic


__version__ = '2.14.200401'


match_can_msg = re.compile(r'''(?ix)^
    (?P<mid>[0-7][0-9A-F]{2}|[01][0-9A-F]{7})
    (?P<data>\ *|\ +(?:[0-9A-F]{2}\ *){,8})
    [\r\n]*$''').match


def line2can(line):
    m = match_can_msg(line.decode())
    if not m: raise ValueError
    mid = int(m.group('mid'), 16)
    data = bytearray.fromhex(m.group('data'))
    is_extended_frame = len(m.group('mid')) == 8
    return mid, data, is_extended_frame


def can2line(mid, data, is_extended_frame=False):
    return ((b'%08X%s\n' if is_extended_frame else b'%03X%s\n')
            % (mid, b' %02X %02X %02X %02X %02X %02X %02X %02X'
                    [:len(data) * 5] % tuple(data)))


class CANHandler(object):

    def can_read_thread(self):
        raise NotImplementedError

    def on_read(self, line, time=None):
        raise NotImplementedError

    def do_write(self, line):
        try:
            mid, data, is_extended_frame = line2can(line)
        except Exception:
            sys.stderr.write('invalid CAN msg %r\n' % line)
            return False
        else:
            return self.do_can_write(*line2can(line))

    def on_can_read(self, mid, data, is_extended_frame, time=None):
        return self.on_read(can2line(mid, data, is_extended_frame), time=time)

    def do_can_write(self, mid, data, is_extended_frame):
        raise NotImplementedError


class KvaserCANHandler(CANHandler):

    use_hardware_clock = False

    canOK = 0
    canERR_NOMSG = -2
    canERR_TXBUFOFL = -13
    canCHANNELDATA_CARD_TYPE = 4
    canHWTYPE_VIRTUAL = 1
    canOPEN_ACCEPT_VIRTUAL = 0x0020
    canBITRATE = {'1M': -1, '500k': -2, '250k': -3, '125k': -4, '100k': -5,
                  '62k': -6, '50k': -7, '83k': -8, '10k': -9}
    canMSG_EXT = 0x0004
    canIOCTL_SET_TIMER_SCALE = 6

    @staticmethod
    def _init_canlib_():
        KvaserCANHandler._init_canlib_ = staticmethod(lambda: None)

        import ctypes
        KvaserCANHandler.ctypes = ctypes
        KvaserCANHandler.MSG_TYPES = tuple(
            ctypes.c_uint8 * i for i in range(9))

        canlib = (ctypes.windll.canlib32 if sys.platform == 'win32' else
                  ctypes.cdll.LoadLibrary(
                      'canlib32.dll' if sys.platform == 'msys' else
                      'libcanlib.so'))

        KvaserCANHandler.canInitializeLibrary = canlib.canInitializeLibrary
        KvaserCANHandler.canInitializeLibrary.restype = None
        KvaserCANHandler.canInitializeLibrary.argtypes = ()

        KvaserCANHandler.canGetChannelData = canlib.canGetChannelData
        KvaserCANHandler.canGetChannelData.restype = ctypes.c_int
        KvaserCANHandler.canGetChannelData.argtypes = (
            ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)

        KvaserCANHandler.canOpenChannel = canlib.canOpenChannel
        KvaserCANHandler.canOpenChannel.restype = ctypes.c_int
        KvaserCANHandler.canOpenChannel.argtypes = (ctypes.c_int, ctypes.c_int)

        KvaserCANHandler.canBusOn = canlib.canBusOn
        KvaserCANHandler.canBusOn.restype = ctypes.c_int
        KvaserCANHandler.canBusOn.argtypes = (ctypes.c_int,)

        KvaserCANHandler.canBusOff = canlib.canBusOff
        KvaserCANHandler.canBusOff.restype = ctypes.c_int
        KvaserCANHandler.canBusOff.argtypes = (ctypes.c_int,)

        KvaserCANHandler.canClose = canlib.canClose
        KvaserCANHandler.canClose.restype = ctypes.c_int
        KvaserCANHandler.canClose.argtypes = (ctypes.c_int,)

        KvaserCANHandler.canSetBusParams = canlib.canSetBusParams
        KvaserCANHandler.canSetBusParams.restype = ctypes.c_int
        KvaserCANHandler.canSetBusParams.argtypes = (
            ctypes.c_int, ctypes.c_long, ctypes.c_uint, ctypes.c_uint,
            ctypes.c_uint, ctypes.c_uint, ctypes.c_uint)

        KvaserCANHandler.canWrite = canlib.canWrite
        KvaserCANHandler.canWrite.restype = ctypes.c_int
        KvaserCANHandler.canWrite.argtypes = (
            ctypes.c_int, ctypes.c_long, ctypes.c_void_p,
            ctypes.c_uint, ctypes.c_uint)

        KvaserCANHandler.canReadWait = canlib.canReadWait
        KvaserCANHandler.canReadWait.restype = ctypes.c_int
        KvaserCANHandler.canReadWait.argtypes = (
            ctypes.c_int, ctypes.POINTER(ctypes.c_long), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong)

        KvaserCANHandler.canIoCtl = canlib.canIoCtl
        KvaserCANHandler.canIoCtl.restype = ctypes.c_int
        KvaserCANHandler.canIoCtl.argtypes = (
            ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint)

        KvaserCANHandler.kvReadTimer = canlib.kvReadTimer
        KvaserCANHandler.kvReadTimer.restype = ctypes.c_int
        KvaserCANHandler.kvReadTimer.argtypes = (
            ctypes.c_int, ctypes.POINTER(ctypes.c_uint))

        KvaserCANHandler.canInitializeLibrary()

    def __init__(self, channel, bitrate='250k', silent=False):
        KvaserCANHandler._init_canlib_()
        super(KvaserCANHandler, self).__init__()
        self.channel = channel
        self.bitrate = bitrate
        self.silent = silent
        self.daemon = True
        self.lock = threading.Lock()  # locked when uninited, writing or closed
        self.lock.acquire()
        self.inited = False

    def can_read_thread(self):

        # check if channel is virtual
        result = self.ctypes.c_uint32()
        status = self.canGetChannelData(
            self.channel, self.canCHANNELDATA_CARD_TYPE,
            self.ctypes.byref(result), self.ctypes.sizeof(result))
        if status != self.canOK:
            raise RuntimeError('channel %d canGetChannelData failed with '
                               'status %r' % (self.channel, status))

        # get a handle for channel
        flags = 0 if result.value != 1 else self.canOPEN_ACCEPT_VIRTUAL
        self.handle = handle = self.canOpenChannel(self.channel, flags)
        if handle < 0:
            raise RuntimeError('channel %d canOpenChannel failed with '
                               'status %r' % (self.channel, handle))

        # set bitrate
        bitrate = self.canBITRATE[self.bitrate.lower().replace('m', 'M')]
        status = self.canSetBusParams(handle, bitrate, 0, 0, 0, 0, 0)
        if status != self.canOK:
            raise RuntimeError('channel %d canSetBusParams failed with '
                               'status %r' % (self.channel, status))

        # turn on channel
        status = self.canBusOn(handle)
        if status != self.canOK:
            raise RuntimeError('channel %d canBusOn failed with '
                               'status %r' % (self.channel, status))

        if self.use_hardware_clock:

            # there looks like a bug when time resolution > 10 us
            resolution = self.ctypes.c_uint(10)
            status = self.canIoCtl(handle, self.canIOCTL_SET_TIMER_SCALE,
                                   self.ctypes.byref(resolution),
                                   self.ctypes.sizeof(resolution))

            # estimate time offset between OS and Kvaser hardware
            t2 = self.ctypes.c_uint()
            t1 = monotonic()
            status = self.kvReadTimer(handle, self.ctypes.byref(t2))
            t3 = monotonic()
            if status != self.canOK:
                raise RuntimeError('channel %d kvReadTimer failed with '
                                   'status %r' % (self.channel, status))
            hardware_clock = t2.value
            time_offset = (t1 + t3) / 2 - hardware_clock * 0.00001

        # enable writing
        self.lock.release()
        self.inited = True

        # reading loop
        mid = self.ctypes.c_long()
        msg = self.MSG_TYPES[8]()
        dlc = self.ctypes.c_uint()
        flag = self.ctypes.c_uint()
        time = self.ctypes.c_ulong()
        args = (handle, self.ctypes.pointer(mid), msg,
                self.ctypes.pointer(dlc), self.ctypes.pointer(flag),
                self.ctypes.pointer(time), 100)
        try:
            while True:
                status = self.canReadWait(*args)
                if status == self.canERR_NOMSG:
                    continue
                elif status != self.canOK:
                    raise RuntimeError('channel %d canReadWait failed with '
                                       'status %r' % (self.channel, status))

                if self.use_hardware_clock:
                    if time.value + 2147483648 < hardware_clock:
                        time_offset += 42949.67296
                    hardware_clock = time.value
                    time_read = time_offset + hardware_clock * 0.00001
                else:
                    time_read = monotonic()

                if not self.on_can_read(mid.value, msg[:dlc.value],
                                        flag.value & self.canMSG_EXT,
                                        time=time_read): break
        finally:
            self.lock.acquire()  # disable writing
            self.canBusOff(handle)
            self.canClose(handle)

    def do_can_write(self, mid, data, is_extended_frame):
        length = len(data)
        data = self.MSG_TYPES[length](*data)
        flag = self.canMSG_EXT if is_extended_frame else 0
        if not self.lock.acquire(not self.inited):  # block when not inted
            raise IOError('write to closed channel %d' % self.channel)
        try:
            status = self.canWrite(self.handle, mid, data, length, flag)
            if status == self.canERR_TXBUFOFL:
                if not self.silent:
                    sys.stderr.write('channel %d buffer full, CAN msg '
                                     'dropped\n' % self.channel)
            elif status != self.canOK:
                raise RuntimeError('channel %d canWrite failed with '
                                   'status %r' % (self.channel, status))
        finally:
            self.lock.release()
        return True


class WitCANHandler(CANHandler):

    @staticmethod
    def _init_serial_():
        WitCANHandler._init_serial_ = staticmethod(lambda: None)
        from serial import Serial
        WitCANHandler.Serial = Serial

    def __init__(self, port, bitrate='250k', uart_bitrate=230400,
                 queue_size=256, silent=False):
        WitCANHandler._init_serial_()
        super(WitCANHandler, self).__init__()
        self.port = port
        self.bitrate = bitrate
        self.uart_bitrate = uart_bitrate
        self.silent = silent
        self.daemon = True
        self.queue = Queue(queue_size)
        self.inited_event = threading.Event()
        self.read_buffer = b''

    def uart_read(self, size=1):
        if len(self.read_buffer) < size:
            self.read_buffer += self.uart.read(
                max(size - len(self.read_buffer), self.uart.in_waiting))
        result = self.read_buffer[:size]
        self.read_buffer = self.read_buffer[size:]
        return result

    def can_read_thread(self):
        self.uart = self.Serial(self.port, self.uart_bitrate, timeout=1)

        # enter config mode
        self.uart.write(b'AT+CG\r\n')
        timeout = monotonic() + 5
        retry = True
        while monotonic() < timeout:
            line = self.uart.readline()
            if line == b'OK\r\n': break
            if retry and not line:
                retry = False
                self.uart.write(b'AT+CG\r\n')
        else:
            raise IOError(self.port + ' failed in AT+CG')

        # set baud
        bitrate = self.bitrate.upper().replace('M', 'KK').replace('K', '000')
        self.uart.write(b'AT+CAN_BAUD=%s\r\n' % bitrate.encode())
        line = self.uart.readline()
        if line != b'OK\r\n':
            raise IOError(self.port + ' failed in AT+CAN_BAUD: %r' % line)

        # enter command mode
        self.uart.write(b'AT+AT\r\n')
        line = self.uart.readline()
        if line.rstrip() != b'OK':
            raise IOError(self.port + ' failed in AT+AT: %r' % line)

        # enable writing
        self.inited_event.set()

        # reading loop
        try:
            self.uart.timeout = None  # set blocking
            while True:
                at = self.uart_read(2)
                if at != b'AT':
                    raise ValueError(self.port + ' read unexpected %r' % at)

                mid_dlc = self.uart_read(5)
                if len(mid_dlc) != 5: raise IOError
                mid, dlc = unpack(b'>LB', mid_dlc)
                flag = mid & 7
                if flag == 0:  # base frame
                    is_extended_frame = False
                    mid >>= 21
                elif flag == 4:  # extended frame
                    is_extended_frame = True
                    mid >>= 3
                else:
                    raise NotImplementedError(
                        self.port + ' get unsupported frame type ' + bin(flag))

                if dlc > 8: raise ValueError('DLC > 8')
                data = self.uart_read(dlc) if dlc else b''
                if len(data) != dlc: raise IOError
                data = bytearray(data)

                crlf = self.uart_read(2)
                if crlf != b'\r\n':
                    raise ValueError(self.port + ' read unexpected %r' % crlf)

                if not self.on_can_read(mid, data, is_extended_frame): break
        finally:
            self.uart.write = len  # disable writing
            self.uart.close()

    def can_write_thread(self):
        self.inited_event.wait()
        while True:
            data = [self.queue.get()]
            while not self.queue.empty():
                data.append(self.queue.get())
            self.uart.write(b''.join(data))

    def do_can_write(self, mid, data, is_extended_frame):
        mid = (mid << 3) | 4 if is_extended_frame else mid << 21
        data = b'AT%s%s\r\n' % (pack(b'>LB', mid, len(data)), bytes(data))
        if self.queue.full():
            self.queue.get(block=False)  # remove oldest item
            if (not self.silent and self.inited_event.is_set()
                    and self.uart.is_open):
                sys.stderr.write(self.port + ' buffer full, CAN msg dropped\n')

        self.queue.put(data)
        return True


class CANAdapter(Application):

    # Kvaser ports: 0, 1, 2, ...
    # Wit ports @ Windows: COM1, COM2, COM3, ...
    # Wit ports @ Linux: /dev/ttyUSB0, /dev/ttyUSB1, /dev/ttyUSB2, ...

    match_port = re.compile(r'''(?ix)^
        (?:|COM|/dev/ttyS|/dev/ttyUSB)[0-9]+
        $''').match

    match_port_cfg = re.compile(r'''(?ix)^
        (?P<port>(?:|COM|/dev/ttyS|/dev/ttyUSB)[0-9]+)
        (?P<bitrate>|:
            (?:1M|500k|250k|125k|100k|62k|50k|83k|10k)
        )
        (?P<mids>|:-|:
            [01]?[0-9a-fA-F]{1,7}
            (?:|-
                [01]?[0-9a-fA-F]{1,7}
            )
            (?:,
                [01]?[0-9a-fA-F]{1,7}
                (?:|-
                    [01]?[0-9a-fA-F]{1,7}
                )
            )*
        )$''').match

    def __init__(self, ports, command=None, bitrate='250k',
                 outfile=None, silent=False):
        super(CANAdapter, self).__init__()
        self.bitrate = bitrate.upper()
        self.silent = silent
        self.lock = threading.Lock()  # locked then writing to opipe
        self.lock.acquire()  # block writing to opipe before inited
        if outfile: self.queue = Queue()  # [ ( line , time ) ]

        def get_port_name(port):
            if isinstance(port, int):
                return 'channel %d' % port
            else:
                return port

        default_port = None
        port2mids = {}  # { port -> [ can id ] }
        mid2port = {}  # { can id -> port }
        bitrates = {}  # { port -> bitrate }
        for i, port in enumerate(ports):
            m = self.match_port_cfg(port)
            if not m: raise ValueError('invalid port ' + repr(port))
            port = m.group('port')
            try:
                port = int(port)  # Kvaser port
            except ValueError:
                pass  # serial port

            if m.group('bitrate'):
                bitrate = m.group('bitrate')[1:].upper()
                bitrate2 = bitrates.get(port)
                if bitrate2 is None: bitrates[port] = bitrate
                elif bitrate2 != bitrate:
                    raise ValueError(
                        'conflict bitrate %s and %s for %s'
                        % (bitrate2, bitrate, get_port_name(port)))

            if port not in port2mids: port2mids[port] = []
            if m.group('mids') == ':-':
                if default_port is not None and default_port != port:
                    raise ValueError(
                        'conflict default %s and %s'
                        % (get_port_name(default_port), get_port_name(port)))
                default_port = port
            elif m.group('mids'):
                for mids in m.group('mids')[1:].split(','):
                    mid1, _, mid2 = mids.partition('-')
                    mid1 = int(mid1, 16)
                    mid2 = int(mid2, 16) if mid2 else mid1
                    for mid in range(min(mid1, mid2), max(mid1, mid2) + 1):
                        port2 = mid2port.get(mid, port)
                        if port2 != port:
                            raise ValueError(
                                'conflict %s and %s for mid %03X'
                                % (get_port_name(port2),
                                   get_port_name(port), mid))
                        mid2port[mid] = port
                        port2mids[port].append(mid)
        if not port2mids: raise ValueError('no CAN port')

        self.default_handler = None
        self.handlers = {}  # { can id -> handler }
        for port, mids in port2mids.items():
            Handler = (KvaserCANHandler if isinstance(port, int) else
                       WitCANHandler)
            handler = Handler(port, bitrates.get(port, self.bitrate))
            if default_port == port: self.default_handler = handler
            for mid in mids: self.handlers[mid] = handler
            handler.on_read = self.on_read
            self.start(handler.can_read_thread)
            if hasattr(handler, 'can_write_thread'):
                self.start(handler.can_write_thread)

        self.outfile = None
        if outfile:
            self.outfile = self.TimedWriter(outfile,
                                            saver='CANAdapter ' + __version__,
                                            close_on_stop=False)
            self.add_stop_listener(lambda: self.queue.put(None))
            self.start(self.file_save_thread, daemon=False)

        self.ipipe, self.opipe = self.get_pipes(command)
        self.start(self.pipe_read_thread, ignore_errors=(IOError, ValueError))

        self.lock.release()  # enable writing to opipe

    def on_read(self, line, time=None):
        try:
            if self.outfile:
                if time is None: time = monotonic()
                self.queue.put((line, time))
            with self.lock:
                self.opipe.write(line)
                self.opipe.flush()
        except (IOError, ValueError):
            return False
        return True

    def do_write(self, line):
        try:
            mid, data, is_extended_frame = line2can(line)
        except Exception:
            if not self.silent:
                sys.stderr.write('invalid CAN msg %r\n' % line)
            return False
        else:
            return self.do_can_write(mid, data, is_extended_frame)

    def do_can_write(self, mid, data, is_extended_frame=False):
        handler = self.handlers.get(mid, self.default_handler)
        if handler:
            if self.outfile:
                self.queue.put((can2line(mid, data, is_extended_frame),
                                monotonic()))
            return handler.do_can_write(mid, data, is_extended_frame)
        elif not self.silent:
            sys.stderr.write('ignored CAN msg %r\n'
                             % can2line(mid, data, is_extended_frame))
            return False

    def pipe_read_thread(self):
        while True:
            line = self.ipipe.readline()
            if not line: break
            self.do_write(line)

    def file_save_thread(self):
        while True:
            self.outfile.flush()
            item = self.queue.get()
            if not item: break
            self.outfile.write(*item)


def parse_args(command=None):

    class PortsCommandAction(argparse.Action):

        def __call__(self, parser, namespace, values, option_string=None):
            if namespace.command:
                namespace.command.extend(values)
            else:
                for i, value in enumerate(values):
                    if CANAdapter.match_port_cfg(value):
                        if not namespace.ports:
                            namespace.ports = [value]
                            for action in parser._actions:
                                if action.dest == 'ports':
                                    action.nargs = argparse.REMAINDER
                        elif value not in namespace.ports:
                            namespace.ports.append(value)
                    else:
                        if not value.startswith('-'):
                            namespace.command = values[i:]
                        else:
                            parser.parse_args(values[i:], namespace)
                        break

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)
    parser.add_argument('-b', '--bitrate', metavar='N',
                        default='250k', choices=sorted(
                            KvaserCANHandler.canBITRATE.keys(),
                            key=KvaserCANHandler.canBITRATE.get),
                        help='CAN bus speed (default = %(default)s)')
    parser.add_argument('-c', '--use-hardware-clock', action='store_true',
                        help='use Kvaser hardware clock for recording')
    parser.add_argument('-o', '--outfile', metavar='FILE',
                        type=argparse.FileType('wb'),
                        help='record CAN bus in a file')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='do not display warnings')
    parser.add_argument('-r', '--realtime', metavar='N', type=int,
                        help='make process realtime with a priority')
    parser.add_argument('ports', metavar='PORT', nargs='+',
                        action=PortsCommandAction, default=[],
                        help='Kvaser CAN channel or '
                             'serial port of WitMotion USB-CAN')
    parser.add_argument('command', metavar='...', nargs=argparse.REMAINDER,
                        action=PortsCommandAction, default=[],
                        help='downstream command')

    args = parser.parse_args(command)
    if not args.ports: parser.error('must specify ports')
    return args


if __name__ == '__main__':

    args = parse_args()

    if args.realtime is not None:
        import realtimizer
        realtimizer.realtimize(args.realtime)

    KvaserCANHandler.use_hardware_clock = args.use_hardware_clock

    CANAdapter(args.ports, args.command, args.bitrate,
               args.outfile, args.silent).mainloop()
