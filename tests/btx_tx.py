"""
Basic BTC transaction serialization and deserialization functionality.

Example usage (finding out if transaction is segwit or not):
>>> import Tx
>>> tx_hex = "01000000020ac14bed7f6224b13b..."
>>> tx = Tx.parse(tx_hex)
>>> print(tx.segwit)

Pure code taken from https://github.com/jimmysong/programmingbitcoin
Type hints were added and it stripped to contain just necessary code for this job.

TODO: should we notify somebody that we are using this code (even though it is not a copypaste)?
TODO: where to put this file?
"""

import hashlib
from io import BytesIO
from typing import Dict, List, Optional, Union


class Tx:
    def __init__(
        self,
        version: int,
        tx_ins: List["TxIn"],
        tx_outs: List["TxOut"],
        locktime: int,
        testnet: bool = False,
        segwit: bool = False,
    ) -> None:
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit

    def __repr__(self) -> str:
        tx_ins = "\n\t".join([str(tx_in) for tx_in in self.tx_ins])
        tx_outs = "\n\t".join([str(tx_out) for tx_out in self.tx_outs])
        return (
            f"tx id: {self.id()}\n"
            f"version: {self.version}\n"
            f"tx_ins:\n\t{tx_ins}\n"
            f"tx_outs:\n\t{tx_outs}\n"
            f"locktime: {self.locktime}"
        )

    def id(self) -> str:
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self) -> bytes:
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s: Union[BytesIO, str, bytes], testnet: bool = False):
        # Unify the stream to be BytesIO
        if isinstance(s, str):
            s = BytesIO(bytes.fromhex(s))
        elif isinstance(s, bytes):
            s = BytesIO(s)

        s.read(4)
        if s.read(1) == b"\x00":
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s: BytesIO, testnet: bool = False) -> "Tx":
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = [TxIn.parse(s) for _ in range(num_inputs)]
        num_outputs = read_varint(s)
        outputs = [TxOut.parse(s) for _ in range(num_outputs)]
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s: BytesIO, testnet: bool = False) -> "Tx":
        version = little_endian_to_int(s.read(4))
        marker = s.read(2)
        if marker != b"\x00\x01":
            raise RuntimeError(f"Not a segwit transaction {marker}")
        num_inputs = read_varint(s)
        inputs = [TxIn.parse(s) for _ in range(num_inputs)]
        num_outputs = read_varint(s)
        outputs = [TxOut.parse(s) for _ in range(num_outputs)]
        for tx_in in inputs:
            num_items = read_varint(s)
            items: List[Union[int, bytes]] = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness = items
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    def serialize(self) -> bytes:
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self) -> bytes:
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self) -> bytes:
        result = int_to_little_endian(self.version, 4)
        result += b"\x00\x01"
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        for tx_in in self.tx_ins:
            result += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if isinstance(item, int):
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        result += int_to_little_endian(self.locktime, 4)
        return result


class TxIn:
    def __init__(
        self,
        prev_tx: bytes,
        prev_index: int,
        script_sig: Optional["Script"] = None,
        sequence: int = 0xFFFFFFFF,
    ) -> None:
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

        self.witness: List[Union[int, bytes]]

    def __repr__(self) -> str:
        return f"{self.prev_tx.hex()}:{self.prev_index}"

    @classmethod
    def parse(cls, s: BytesIO) -> "TxIn":
        """Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        """
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is an integer in 4 bytes, little endian
        prev_index = little_endian_to_int(s.read(4))
        # use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        """Returns the byte serialization of the transaction input"""
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result


class TxOut:
    def __init__(self, amount: int, script_pubkey: "Script") -> None:
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self) -> str:
        return f"{self.amount}:{self.script_pubkey}"

    @classmethod
    def parse(cls, s: BytesIO) -> "TxOut":
        """Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        """
        # amount is an integer in 8 bytes, little endian
        amount = little_endian_to_int(s.read(8))
        # use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)

    def serialize(self) -> bytes:
        """Returns the byte serialization of the transaction output"""
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


class Script:
    def __init__(self, cmds: Optional[List[Union[int, bytes]]] = None) -> None:
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self) -> str:
        result: List[str] = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                if cmd in OP_CODE_NAMES:
                    name = OP_CODE_NAMES[cmd]
                else:
                    name = f"OP_[{cmd}]"
                result.append(name)
            else:
                result.append(cmd.hex())
        return " ".join(result)

    def __add__(self, other: "Script") -> "Script":
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s: BytesIO) -> "Script":
        # get the length of the entire field
        length = read_varint(s)
        # initialize the cmds array
        cmds: List[Union[int, bytes]] = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have an cmd set n to be the current byte
                n = current_byte
                # add the next n bytes as an cmd
                cmds.append(s.read(n))
                # increase the count by n
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError("parsing script failed")
        return cls(cmds)

    def raw_serialize(self) -> bytes:
        # initialize what we'll send back
        result = b""
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if isinstance(cmd, int):
                # turn the cmd into a single byte integer using int_to_little_endian
                result += int_to_little_endian(cmd, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)
                # for large lengths, we have to use a pushdata opcode
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError("too long an cmd")
                result += cmd
        return result

    def serialize(self) -> bytes:
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result


def hash256(s: bytes) -> bytes:
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def int_to_little_endian(n: int, length: int) -> bytes:
    """endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length"""
    return n.to_bytes(length, "little")


def little_endian_to_int(b: bytes) -> int:
    """little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer"""
    return int.from_bytes(b, "little")


def encode_varint(i: int) -> bytes:
    """encodes an integer as a varint"""
    if i < 0xFD:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError(f"integer too large: {i}")


def read_varint(s: BytesIO) -> int:
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


OP_CODE_NAMES: Dict[int, str] = {
    0: "OP_0",
    76: "OP_PUSHDATA1",
    77: "OP_PUSHDATA2",
    78: "OP_PUSHDATA4",
    79: "OP_1NEGATE",
    81: "OP_1",
    82: "OP_2",
    83: "OP_3",
    84: "OP_4",
    85: "OP_5",
    86: "OP_6",
    87: "OP_7",
    88: "OP_8",
    89: "OP_9",
    90: "OP_10",
    91: "OP_11",
    92: "OP_12",
    93: "OP_13",
    94: "OP_14",
    95: "OP_15",
    96: "OP_16",
    97: "OP_NOP",
    99: "OP_IF",
    100: "OP_NOTIF",
    103: "OP_ELSE",
    104: "OP_ENDIF",
    105: "OP_VERIFY",
    106: "OP_RETURN",
    107: "OP_TOALTSTACK",
    108: "OP_FROMALTSTACK",
    109: "OP_2DROP",
    110: "OP_2DUP",
    111: "OP_3DUP",
    112: "OP_2OVER",
    113: "OP_2ROT",
    114: "OP_2SWAP",
    115: "OP_IFDUP",
    116: "OP_DEPTH",
    117: "OP_DROP",
    118: "OP_DUP",
    119: "OP_NIP",
    120: "OP_OVER",
    121: "OP_PICK",
    122: "OP_ROLL",
    123: "OP_ROT",
    124: "OP_SWAP",
    125: "OP_TUCK",
    130: "OP_SIZE",
    135: "OP_EQUAL",
    136: "OP_EQUALVERIFY",
    139: "OP_1ADD",
    140: "OP_1SUB",
    143: "OP_NEGATE",
    144: "OP_ABS",
    145: "OP_NOT",
    146: "OP_0NOTEQUAL",
    147: "OP_ADD",
    148: "OP_SUB",
    154: "OP_BOOLAND",
    155: "OP_BOOLOR",
    156: "OP_NUMEQUAL",
    157: "OP_NUMEQUALVERIFY",
    158: "OP_NUMNOTEQUAL",
    159: "OP_LESSTHAN",
    160: "OP_GREATERTHAN",
    161: "OP_LESSTHANOREQUAL",
    162: "OP_GREATERTHANOREQUAL",
    163: "OP_MIN",
    164: "OP_MAX",
    165: "OP_WITHIN",
    166: "OP_RIPEMD160",
    167: "OP_SHA1",
    168: "OP_SHA256",
    169: "OP_HASH160",
    170: "OP_HASH256",
    171: "OP_CODESEPARATOR",
    172: "OP_CHECKSIG",
    173: "OP_CHECKSIGVERIFY",
    174: "OP_CHECKMULTISIG",
    175: "OP_CHECKMULTISIGVERIFY",
    176: "OP_NOP1",
    177: "OP_CHECKLOCKTIMEVERIFY",
    178: "OP_CHECKSEQUENCEVERIFY",
    179: "OP_NOP4",
    180: "OP_NOP5",
    181: "OP_NOP6",
    182: "OP_NOP7",
    183: "OP_NOP8",
    184: "OP_NOP9",
    185: "OP_NOP10",
}
