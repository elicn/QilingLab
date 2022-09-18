#!/usr/bin/python3

# Yet another solver program for QilingLab (x86-64).
#
# Run sovler:
#   PYTHONPATH=/path/to/qiling python3 solver.py qilinglab-x86_64 /path/to/rootfs/x8664_linux
#
# Linux x86-64 rootfs can be found at examples/rootfs/x8664_linux, under qiling directory
# Get QilingLab executable from: https://www.shielder.it/blog/2021/07/qilinglab-release/

import argparse
import io
from typing import Callable, Iterable, Mapping, Tuple

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.const import *
from qiling.os.linux.syscall_nums import SYSCALL_NR
from qiling.os.mapper import QlFsMappedObject


def solve01(ql: Qiling):
    """The target address is not mapped; map the page that contains it first
    and then set the required value.
    """

    ptr = 0x1337
    val = 1337

    aligned_addr = ql.mem.align(ptr)
    aligned_size = ql.mem.align_up(ql.arch.pointersize)

    ql.mem.map(aligned_addr, aligned_size)
    ql.mem.write_ptr(ptr, val)


def solve02(ql: Qiling):
    """The uname system call writes several consecutive entries to memory, each
    of which is 65 bytes in size. Only the 1st and 4th entries are compared,
    where the 1st one should be identical to the original system call result.

    We hook the system call on-exit and patch the 4th entry so it would match
    the required string.
    """

    def __uname(ql: Qiling, buf: int, retval: int):
        ql.mem.write(buf + 3 * 65, b'ChallengeStart')

    ql.os.set_syscall(SYSCALL_NR.uname, __uname, QL_INTERCEPT.EXIT)


def solve03(ql: Qiling):
    """The code pulls 32 bytes from /dev/urandom and then pulls an additional
    one. It checks that the last byte is not repeated in the first chunk and
    proceeds to ask getrandom to generate 32 random bytes.

    The first 32 bytes pulled from urandom are expected to be identical to the
    ones received from getrandom.

    To make sure the "random" numbers do not repeat themselves, we simply use a
    running index.
    """

    bytespool = bytes(range(64))

    def __getrandom(ql: Qiling):
        params = ql.os.resolve_fcall_params({
            'buf'    : POINTER,
            'buflen' : SIZE_T,
            'flags'  : UINT
        })

        buf = params['buf']
        buflen = params['buflen']

        randbytes = bytespool[:buflen]
        ql.mem.write(buf, randbytes)

        ql.os.fcall.cc.setReturnValue(len(randbytes))

    class MyUrandom(QlFsMappedObject):
        def __init__(self):
            super().__init__()

            self.pos = 0

        def read(self, size: int) -> bytes:
            randbytes = bytespool[self.pos:self.pos + size]
            self.pos += size

            return randbytes

        def close(self):
            return 0

    ql.add_fs_mapper("/dev/urandom", MyUrandom())

    ql.os.set_api('getrandom', __getrandom, QL_INTERCEPT.CALL)


def solve04(ql: Qiling):
    """To enter the loop var_8h should be set to any value higher than 0.
    We intercept the reads from that location in memory and set it to 1.

    Note that the hook removes itself after the first time it is called to
    prevent future reads from the stack location from triggering this hook.

    Also, when entering a function its stack frame is not yet set, so we
    refer var_8h using rsp instead of rbp.
    """

    def __patch_var_8h(ql: Qiling, access: int, addr: int, size: int, value: int):
        ql.mem.write_ptr(addr, 1, 4)

        hret.remove()

    hret = ql.hook_mem_read(__patch_var_8h, begin=ql.arch.regs.rsp - 16)


def solve05(ql: Qiling):
    """All random generated values are expected to be 0.
    Hook the lib function and make it return only zeros.
    """

    def __rand(ql: Qiling):
        ql.os.fcall.cc.setReturnValue(0)

    ql.os.set_api('rand', __rand, QL_INTERCEPT.CALL)


def solve06(ql: Qiling):
    """This one quite resembles challenge4 as it requires the same practice of
    intercepting reads from a local variable and patching the value.

    Same remarks apply here as well.
    """

    def __patch_var_5h(ql: Qiling, access: int, addr: int, size: int, value: int):
        ql.mem.write_ptr(addr, 0, 4)

        hret.remove()

    hret = ql.hook_mem_read(__patch_var_5h, begin=ql.arch.regs.rsp - 5)


def solve07(ql: Qiling):
    """Avoid sleeping by hooking the lib function and make it return immediately.
    """

    def __sleep(ql: Qiling):
        pass

    ql.os.set_api('sleep', __sleep, QL_INTERCEPT.CALL)


def solve08(ql: Qiling):
    """A meaningless structure is initialized by the challenge code, and
    includes a pointer to a buffer passed as an argument to the challenge
    function (denoted here as "ptr2").

    That buffer needs to hold a non-zero value for the challenge to pass.
    """

    def __patch_struct(ql: Qiling):
        # var_8h -> {
        #   0x00:	void*	ptr1	# -> b'Random data'
        #   0x08:	int32	val1	# = 0x0000539
        #   0x0c:	int128	val2	# = *((int32*) 0x00001a98)
        #   0x10:	void*	ptr2	# -> arg1
        # }

        var_8h = ql.mem.read_ptr(ql.arch.regs.rbp - 0x08)
        ptr2 = ql.mem.read_ptr(var_8h + 0x10)

        ql.mem.write(ptr2, b'\x01')
        hret.remove()

    # hook the nop instruction before the function epilogue to remain in the
    # same stack frame
    hret = ql.hook_address(__patch_struct, ql.arch.regs.arch_pc + 0x71)


def solve09(ql: Qiling):
    """A mixed-case string needs to remain intact after applying a 'tolower'
    on all of its characters. That requires nullifying tolower and making it
    return the exact same character every time.
    """

    def __tolower(ql: Qiling):
        params = ql.os.resolve_fcall_params({
            'c' : INT
        })

        ql.os.fcall.cc.setReturnValue(params['c'])

    ql.os.set_api('tolower', __tolower, QL_INTERCEPT.CALL)


def solve10(ql: Qiling):
    """The challenge code reads from '/proc/self/cmdline' and expects to find
    'qilinglab' as argv[0].

    All we need is to map a fake file obj and make it return a pre-defined content.
    The file object might be further extended to support more argv strings.
    """

    ql.add_fs_mapper("/proc/self/cmdline", io.BytesIO(b'qilinglab'))


def solve11(ql: Qiling):
    """the CPUID instruction called with leaf function 0x40000000 is expected
    to set specific values to ebx, ecx and edx that read together as 'QilingLab   '.
    """

    def __patch_cpuid(ql: Qiling):
        # modify only if we have the correct cpuid leaf
        if ql.arch.regs.eax == 0x40000000:
            payload = b'QilingLab'.ljust(12)

            ql.arch.regs.ebx = ql.unpack32(payload[0:4])    # 0x696c6951
            ql.arch.regs.ecx = ql.unpack32(payload[4:8])    # 0x614c676e
            ql.arch.regs.edx = ql.unpack32(payload[8:12])   # 0x20202062

            # skip the cpuid instruction
            ql.arch.regs.arch_pc += 2

    # the cpuid instruction is located at offset 0x36 from function entry
    ql.hook_address(__patch_cpuid, ql.arch.regs.arch_pc + 0x36)


def map_symbols(ql: Qiling, symsmap: Mapping[int, str]):
    """Allow more intuitive hooking by using symbols names, and support
    enhanced tracing.

    For enhanced tracing see: qiling/extensions/trace.py
    """

    ba = ql.loader.images[0].base
    relmap = dict((ba + off, sym) for off, sym in symsmap.items())

    setattr(ql.loader, 'symsmap', relmap)


def resolve(ql: Qiling, sym: str) -> int:
    """Resolve symbol by name.
    """

    symsmap: Mapping[int, str] = getattr(ql.loader, 'symsmap', {})

    address = next((o for o, s in symsmap.items() if s == sym), None)
    assert address is not None, f'could not find symbol "{symbol}"'

    return address


def one_time_hook(ql: Qiling, callback: Callable, address: int):
    """Set a self-disposeable hook on a specific address.
    One-time hooks help reducing hooks clutter.
    """

    def __setup(ql: Qiling):
        callback(ql)
        hsetup.remove()

    hsetup = ql.hook_address(__setup, address)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Yet another solver program for QilingLab')
    parser.add_argument('labfile', help='path to qiling-lab binary')
    parser.add_argument('rootfs', help='path to x86-64 linux rootfs')

    args = parser.parse_args()

    ql = Qiling([args.labfile], args.rootfs, verbose=QL_VERBOSE.OFF)

    # symbols offsets were collected using:
    #   rabin2 -s qilinglab-x86_64 | grep "challenge" | awk '{print $2, $7}' | sort
    #
    # but may also be collected using:
    #   readelf -s qilinglab-x86_64 | grep "challenge" | awk '{print $2, $8}' | sort
    #
    # more symbols may be added to the mapping below.
    offsets: Mapping[int, str] = {
        0x0b8a: 'sym.challenge1',
        0x0bb6: 'sym.challenge2',
        0x0d31: 'sym.challenge3',
        0x0e1d: 'sym.challenge4',
        0x0e4b: 'sym.challenge5',
        0x0ef6: 'sym.challenge6',
        0x0f24: 'sym.challenge7',
        0x0f44: 'sym.challenge8',
        0x0fb8: 'sym.challenge9',
        0x1078: 'sym.challenge10',
        0x1159: 'sym.challenge11'
    }

    map_symbols(ql, offsets)

    solvers: Iterable[Tuple[str, Callable]] = (
        ('sym.challenge1',  solve01),
        ('sym.challenge2',  solve02),
        ('sym.challenge3',  solve03),
        ('sym.challenge4',  solve04),
        ('sym.challenge5',  solve05),
        ('sym.challenge6',  solve06),
        ('sym.challenge7',  solve07),
        ('sym.challenge8',  solve08),
        ('sym.challenge9',  solve09),
        ('sym.challenge10', solve10),
        ('sym.challenge11', solve11)
    )

    # set up challenges solvers
    for symbol, solver in solvers:
        address = resolve(ql, symbol)

        one_time_hook(ql, solver, address)

    # BUG: hooks set from within a hook are overlooked by unicorn if bound to an address
    # within the same basic block. an existing hook_code set beforehand will force unicorn
    # to refresh on instruction boundary instead of basic block, and pick that hook up.
    #
    # this dummy hook is used to allow unicorn pick up the hook set for challenge 11, though
    # it slows down the execution. to minimize the slow down effect as much as possible, we
    # set it just before entering the challenge11 function.
    #
    # <WORKAROUND>
    def setup_workaround(ql: Qiling):
        def dummy(ql: Qiling, address: int, size: int):
            pass

        ql.hook_code(dummy)

    call_to_challenge11 = ql.loader.images[0].base + 0x1581
    ql.hook_address(setup_workaround, call_to_challenge11)
    # </WORKAROUND>

    # do the magic
    ql.run()
