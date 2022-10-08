# SPDX-License-Identifier: BSD-3-Clause

import functools
import jsonschema
import os
import random
import socket
import struct
import yaml

#
# Generic Netlink code which should really be in some library, but I can't quickly find one.
#


class Netlink:
    SOL_NETLINK = 270

    NETLINK_CAP_ACK = 10
    NETLINK_EXT_ACK = 11

    NLMSG_ERROR = 2
    NLMSG_DONE = 3

    NLM_F_REQUEST = 1
    NLM_F_ACK = 4
    NLM_F_ROOT = 0x100
    NLM_F_MATCH = 0x200
    NLM_F_APPEND = 0x800

    NLM_F_CAPPED = 0x100
    NLM_F_ACK_TLVS = 0x200

    NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

    NLA_F_NESTED = 0x8000
    NLA_F_NET_BYTEORDER = 0x4000

    NLA_TYPE_MASK = NLA_F_NESTED | NLA_F_NET_BYTEORDER

    # Genetlink defines
    NETLINK_GENERIC = 16

    GENL_ID_CTRL = 0x10

    # nlctrl
    CTRL_CMD_GETFAMILY = 3

    CTRL_ATTR_FAMILY_ID = 1
    CTRL_ATTR_FAMILY_NAME = 2

    # Extack types
    NLMSGERR_ATTR_MSG = 1
    NLMSGERR_ATTR_OFFS = 2
    NLMSGERR_ATTR_COOKIE = 3
    NLMSGERR_ATTR_POLICY = 4
    NLMSGERR_ATTR_MISS_TYPE = 5
    NLMSGERR_ATTR_MISS_NEST = 6


class NlAttr:
    def __init__(self, raw, offset):
        self._len, self._type = struct.unpack("HH", raw[offset:offset + 4])
        self.type = self._type & ~Netlink.NLA_TYPE_MASK
        self.payload_len = self._len
        self.full_len = (self.payload_len + 3) & ~3
        self.raw = raw[offset + 4:offset + self.payload_len]

    def as_u16(self):
        return struct.unpack("H", self.raw)[0]

    def as_u32(self):
        return struct.unpack("I", self.raw)[0]

    def as_strz(self):
        return self.raw.decode('ascii')[:-1]

    def __repr__(self):
        return f"[type:{self.type} len:{self._len}] {self.raw}"


class NlAttrs:
    def __init__(self, msg):
        self.attrs = []

        offset = 0
        while offset < len(msg):
            attr = NlAttr(msg, offset)
            offset += attr.full_len
            self.attrs.append(attr)

    def __iter__(self):
        yield from self.attrs

    def __repr__(self):
        msg = ''
        for a in self.attrs:
            if msg:
                msg += '\n'
            msg += repr(a)
        return msg


class NlMsg:
    def __init__(self, msg, offset, attr_space=None):
        self.hdr = msg[offset:offset + 16]

        self.nl_len, self.nl_type, self.nl_flags, self.nl_seq, self.nl_portid = \
            struct.unpack("IHHII", self.hdr)

        self.raw = msg[offset + 16:offset + self.nl_len]

        self.error = 0
        self.done = 0

        extack_off = None
        if self.nl_type == Netlink.NLMSG_ERROR:
            self.error = struct.unpack("i", self.raw[0:4])[0]
            self.done = 1
            extack_off = 20
        elif self.nl_type == Netlink.NLMSG_DONE:
            self.done = 1
            extack_off = 4

        self.extack = None
        if self.nl_flags & Netlink.NLM_F_ACK_TLVS and extack_off:
            self.extack = dict()
            extack_attrs = NlAttrs(self.raw[extack_off:])
            for extack in extack_attrs:
                if extack.type == Netlink.NLMSGERR_ATTR_MSG:
                    self.extack['msg'] = extack.as_strz()
                elif extack.type == Netlink.NLMSGERR_ATTR_MISS_TYPE:
                    self.extack['miss-type'] = extack.as_u32()
                elif extack.type == Netlink.NLMSGERR_ATTR_MISS_NEST:
                    self.extack['miss-nest'] = extack.as_u32()
                else:
                    if 'unknown' not in self.extack:
                        self.extack['unknown'] = []
                    self.extack['unknown'].append(extack)

            if attr_space:
                # We don't have the ability to parse nests yet, so only do global
                if 'miss-type' in self.extack and 'miss-nest' not in self.extack:
                    miss_type = self.extack['miss-type']
                    if len(attr_space.attr_list) > miss_type:
                        spec = attr_space.attr_list[miss_type]
                        desc = spec['name']
                        if 'doc' in spec:
                            desc += f" ({spec['doc']})"
                        self.extack['miss-type'] = desc

    def __repr__(self):
        msg = f"nl_len = {self.nl_len} nl_flags = 0x{self.nl_flags:x} nl_type = {self.nl_type}\n"
        if self.error:
            msg += '\terror: ' + str(self.error)
        if self.extack:
            msg += '\textack: ' + repr(self.extack)
        return msg


class NlMsgs:
    def __init__(self, data, attr_space=None):
        self.msgs = []

        offset = 0
        while offset < len(data):
            msg = NlMsg(data, offset, attr_space=attr_space)
            offset += msg.nl_len
            self.msgs.append(msg)

    def __iter__(self):
        yield from self.msgs


genl_family_name_to_id = None


def _genl_msg(nl_type, nl_flags, genl_cmd, genl_version):
    # we prepend length in _genl_msg_finalize()
    nlmsg = struct.pack("HHII", nl_type, nl_flags, random.randint(1, 1024), 0)
    genlmsg = struct.pack("bbH", genl_cmd, genl_version, 0)
    return nlmsg + genlmsg


def _genl_msg_finalize(msg):
    return struct.pack("I", len(msg) + 4) + msg


def _genl_load_families():
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, Netlink.NETLINK_GENERIC) as sock:
        sock.setsockopt(Netlink.SOL_NETLINK, Netlink.NETLINK_CAP_ACK, 1)

        msg = _genl_msg(Netlink.GENL_ID_CTRL, Netlink.NLM_F_REQUEST | Netlink.NLM_F_ACK | Netlink.NLM_F_DUMP,
                        Netlink.CTRL_CMD_GETFAMILY, 1)
        msg = _genl_msg_finalize(msg)

        sock.send(msg, 0)

        global genl_family_name_to_id
        genl_family_name_to_id = dict()

        while True:
            reply = sock.recv(128 * 1024)
            nms = NlMsgs(reply)
            for nl_msg in nms:
                if nl_msg.error:
                    print("Netlink error:", nl_msg.error)
                    return
                if nl_msg.done:
                    return

                gm = GenlMsg(nl_msg)
                fam_id = None
                fam_name = None
                for attr in gm.raw_attrs:
                    if attr.type == Netlink.CTRL_ATTR_FAMILY_ID:
                        fam_id = attr.as_u16()
                    elif attr.type == Netlink.CTRL_ATTR_FAMILY_NAME:
                        fam_name = attr.as_strz()
                if fam_id is not None and fam_name is not None:
                    genl_family_name_to_id[fam_name] = fam_id


class GenlMsg:
    def __init__(self, nl_msg):
        self.nl = nl_msg

        self.hdr = nl_msg.raw[0:4]
        self.raw = nl_msg.raw[4:]

        self.genl_cmd, self.genl_version, _ = struct.unpack("bbH", self.hdr)

        self.raw_attrs = NlAttrs(self.raw)

    def __repr__(self):
        msg = repr(self.nl)
        msg += f"\tgenl_cmd = {self.genl_cmd} genl_ver = {self.genl_version}\n"
        for a in self.raw_attrs:
            msg += '\t\t' + repr(a) + '\n'
        return msg


class GenlFamily:
    def __init__(self, family_name):
        self.family_name = family_name

        global genl_family_name_to_id
        if genl_family_name_to_id is None:
            _genl_load_families()

        self.family_id = genl_family_name_to_id[family_name]

#
# YNL implementation details.
#


class YnlAttrSpace:
    def __init__(self, family, yaml):
        self.yaml = yaml

        self.attrs = dict()
        self.name = self.yaml['name']
        self.subspace_of = self.yaml['subset-of'] if 'subspace-of' in self.yaml else None

        val = 0
        max_val = 0
        for elem in self.yaml['attributes']:
            if 'value' in elem:
                val = elem['value']
            else:
                elem['value'] = val
            if val > max_val:
                max_val = val
            val += 1

            self.attrs[elem['name']] = elem

        self.attr_list = [None] * (max_val + 1)
        for elem in self.yaml['attributes']:
            self.attr_list[elem['value']] = elem

    def __getitem__(self, key):
        return self.attrs[key]

    def __contains__(self, key):
        return key in self.yaml

    def __iter__(self):
        yield from self.attrs

    def items(self):
        return self.attrs.items()


class YnlFamily:
    def __init__(self, def_path, schema=None):
        with open(def_path, "r") as stream:
            self.yaml = yaml.safe_load(stream)

        if schema:
            with open(schema, "r") as stream:
                schema = yaml.safe_load(stream)

            jsonschema.validate(self.yaml, schema)

        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, Netlink.NETLINK_GENERIC)
        self.sock.setsockopt(Netlink.SOL_NETLINK, Netlink.NETLINK_CAP_ACK, 1)
        self.sock.setsockopt(Netlink.SOL_NETLINK, Netlink.NETLINK_EXT_ACK, 1)

        self._ops = dict()
        self._spaces = dict()

        for elem in self.yaml['attribute-sets']:
            self._spaces[elem['name']] = YnlAttrSpace(self, elem)

        async_separation = 'async-prefix' in self.yaml['operations']
        val = 0
        for elem in self.yaml['operations']['list']:
            if not (async_separation and ('notify' in elem or 'event' in elem)):
                if 'value' in elem:
                    val = elem['value']
                else:
                    elem['value'] = val
                val += 1

            self._ops[elem['name']] = elem

            op_name = elem['name'].replace('-', '_')

            bound_f = functools.partial(self._op, elem['name'])
            setattr(self, op_name, bound_f)

        self.family = GenlFamily(self.yaml['name'])

    def _add_attr(self, space, name, value):
        attr = self._spaces[space][name]
        nl_type = attr['value']
        if attr["type"] == 'nest':
            nl_type |= Netlink.NLA_F_NESTED
            attr_payload = b''
            for subname, subvalue in value.items():
                attr_payload += self._add_attr(attr['nested-attributes'], subname, subvalue)
        elif attr["type"] == 'u32':
            attr_payload = struct.pack("I", int(value))
        elif attr["type"] == 'string':
            attr_payload = str(value).encode('ascii') + b'\x00'
        else:
            raise Exception(f'Unknown type at {space} {name} {value} {attr["type"]}')

        pad = b'\x00' * ((4 - len(attr_payload) % 4) % 4)
        return struct.pack('HH', len(attr_payload) + 4, nl_type) + attr_payload + pad

    def _decode(self, attrs, space):
        attr_space = self._spaces[space]
        rsp = dict()
        for attr in attrs:
            attr_spec = attr_space.attr_list[attr.type]
            if attr_spec["type"] == 'nest':
                subdict = self._decode(NlAttrs(attr.raw), attr_spec['nested-attributes'])
                rsp[attr_spec['name']] = subdict
            elif attr_spec['type'] == 'u32':
                rsp[attr_spec['name']] = attr.as_u32()
            elif attr_spec["type"] == 'string':
                rsp[attr_spec['name']] = attr.as_strz()
            else:
                raise Exception(f'Unknown {attr.type} {attr_spec["name"]} {attr_spec["type"]}')
        return rsp

    def _op(self, method, vals, dump=False):
        op = self._ops[method]

        nl_flags = Netlink.NLM_F_REQUEST | Netlink.NLM_F_ACK
        if dump:
            nl_flags |= Netlink.NLM_F_DUMP

        msg = _genl_msg(self.family.family_id, nl_flags, op['value'], 1)
        for name, value in vals.items():
            msg += self._add_attr(op['attribute-set'], name, value)
        msg = _genl_msg_finalize(msg)

        self.sock.send(msg, 0)

        done = False
        rsp = []
        while not done:
            reply = self.sock.recv(128 * 1024)
            nms = NlMsgs(reply, attr_space=self._spaces[op['attribute-set']])
            for nl_msg in nms:
                if nl_msg.error:
                    print("Netlink error:", os.strerror(-nl_msg.error))
                    print(nl_msg)
                    return
                if nl_msg.done:
                    done = True
                    break

                gm = GenlMsg(nl_msg)
                rsp.append(self._decode(gm.raw_attrs, op['attribute-set']))

        if not rsp:
            return None
        return rsp[0] if len(rsp) == 1 else rsp
