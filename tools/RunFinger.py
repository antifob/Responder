#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sys
import struct
import datetime
import multiprocessing
import os
import errno
import optparse
import sqlite3
from RunFingerPackets import *
from odict import OrderedDict
from socket import *
from odict import OrderedDict

__version__ = "1.8"

PROGBASE = os.path.abspath(os.path.dirname(__file__))


parser = optparse.OptionParser(usage='python %prog -i 10.10.10.224\nor:\npython %prog -i 10.10.10.0/24', version=__version__, prog=sys.argv[0])

parser.add_option('-i', '--ip', action="store", help="Target IP address or class C", dest="TARGET", metavar="10.10.10.224", default=None)
parser.add_option('-f', '--filename', action="store", help="Target file", dest="Filename", metavar="ips.txt", default=None)
parser.add_option('-t', '--timeout', action="store", help="Timeout for all connections. Use this option to fine tune Runfinger.", dest="Timeout", type="float", metavar="0.9", default=2)
parser.add_option('-d', '--database', action='store', help='Database to store results', dest='DB', default=os.path.join(PROGBASE, 'RunFinger.db'))

options, args = parser.parse_args()

if options.TARGET is None and options.Filename is None:
    print("\n-i Mandatory option is missing, please provide a target or target range.\n")
    parser.print_help()
    exit(1)

Timeout = options.Timeout
Host = options.TARGET
Filename = options.Filename
SMB1 = "True"
SMB2signing = "False"


class Packet():
    fields = OrderedDict([
    ])

    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in list(kw.items()):
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v

    def __str__(self):
        return "".join(map(str, list(self.fields.values())))


if (sys.version_info > (3, 0)):
    PY2OR3 = "PY3"
else:
    PY2OR3 = "PY2"


def StructWithLenPython2or3(endian,data):
    if PY2OR3 == "PY2":
        return struct.pack(endian, data)
    else:
        return struct.pack(endian, data).decode('latin-1')


def NetworkSendBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return bytes(str(data), 'latin-1')


def NetworkRecvBufferPython2or3(data):
    if PY2OR3 == "PY2":
        return str(data)
    else:
        return str(data.decode('latin-1'))


def longueur(payload):
    return StructWithLenPython2or3(">i", len(''.join(payload)))


def ParseNegotiateSMB2Ans(data):
    return data[4:8] == b"\xfeSMB"


def SMB2SigningMandatory(data):
    global SMB2signing
    SMB2signing = "True" if data[70] == "\x03" else "False"


def WorkstationFingerPrint(data):
    return {
        b"\x04\x00"    :"Windows 95",
        b"\x04\x0A"    :"Windows 98",
        b"\x04\x5A"    :"Windows ME",
        b"\x05\x00"    :"Windows 2000",
        b"\x05\x01"    :"Windows XP",
        b"\x05\x02"    :"Windows XP(64-Bit)/Windows 2003",
        b"\x06\x00"    :"Windows Vista/Server 2008",
        b"\x06\x01"    :"Windows 7/Server 2008R2",
        b"\x06\x02"    :"Windows 8/Server 2012",
        b"\x06\x03"    :"Windows 8.1/Server 2012R2",
        b"\x0A\x00"    :"Windows 10/Server 2016/2019 (check build)",
     }.get(data, 'Other than Microsoft')


def GetOsBuildNumber(data):
    return struct.unpack("<h",data)[0]


def SaveToDb(result):
    cols = [
        'timestamp', 'Protocol', 'Host', 'WindowsVersion',
        'OsVer', 'DomainJoined', 'Bootime', 'Signing',
        'NullSess', 'IsRPDOn', 'SMB1', 'MSSQL'
    ]

    db = sqlite3.connect(options.DB)
    qr = ',{}'.join(['{} TEXT'.format(c) for c in cols])
    db.execute('CREATE TABLE IF NOT EXISTS RunFinger ({})'.format(qr))
    cursor.commit()


    # normalization and ordering
    vals = [result[c] if c in result else '' for c in cols]
    del vals[timestamp]

    cursor.text_factory = sqlite3.Binary
    cursor.execute('''
        INSERT INTO RunFinger
        VALUES(datetime('now'),?,?,?,?,?,?,?,?,?,?,?)
    ''', params)
    cursor.commit()
    cursor.close()


def ParseSMBNTLM2Exchange(data, host, bootime, signing):  #Parse SMB NTLMSSP Response
    data = data.encode('latin-1')
    SSPIStart  = data.find(b'NTLMSSP')
    SSPIString = data[SSPIStart:]
    TargetNameLen = struct.unpack('<H',data[SSPIStart+12:SSPIStart+14])[0]
    TargetNameOffset = struct.unpack('<L',data[SSPIStart+16:SSPIStart+20])[0]
    Domain = SSPIString[TargetNameOffset:TargetNameOffset+TargetNameLen].decode('UTF-16LE')

    AvPairsLen        = struct.unpack('<H',data[SSPIStart+40:SSPIStart+42])[0]
    AvPairsOffset     = struct.unpack('<L',data[SSPIStart+44:SSPIStart+48])[0]
    #AvPairs          = SSPIString[AvPairsOffset:AvPairsOffset+AvPairsLen].decode('UTF-16LE')
    WindowsVers       = WorkstationFingerPrint(data[SSPIStart+48:SSPIStart+50])
    WindowsBuildVers  = GetOsBuildNumber(data[SSPIStart+50:SSPIStart+52])
    DomainGrab((host, 445))
    RDP = IsServiceOn((host,3389))
    SQL = IsServiceOn((host,1433))
    print(("[SMB2]:['{}', Os:'{}', Build:'{}', Domain:'{}', Bootime: '{}', Signing:'{}', RDP:'{}', SMB1:'{}', MSSQL:'{}']".format(host, WindowsVers, str(WindowsBuildVers), Domain, Bootime, signing, RDP,SMB1, SQL)))
    SaveToDb({
        'Protocol': '[SMB2]',
        'Host': host,
        'WindowsVersion': WindowsVers,
        'OsVer': str(WindowsBuildVers),
        'DomainJoined': Domain,
        'Bootime': Bootime,
        'Signing': signing,
        'NullSess': 'N/A',
        'IsRDPOn': RDP,
        'SMB1': SMB1,
        'MSSQL': SQL,
    })


def GetBootTime(data):
    data = data.encode('latin-1')
    Filetime = int(struct.unpack('<q',data)[0])
    if Filetime == 0:  # server may not disclose this info
        return 0, "Unknown"
    t = divmod(Filetime - 116444736000000000, 10000000)
    time = datetime.datetime.fromtimestamp(t[0])
    return time, time.strftime('%Y-%m-%d %H:%M:%S')


def IsDCVuln(t, host):
    if t[0] == 0:
        return "Unknown"
    Date = datetime.datetime(2014, 11, 17, 0, 30)
    if t[0] < Date:
        return "This system may be vulnerable to MS14-068"
    Date = datetime.datetime(2017, 3, 14, 0, 30)
    if t[0] < Date:
        return "This system may be vulnerable to MS17-010"
    return t[1]

#####################

def IsSigningEnabled(data):
    return 'True' if data[39] == "\x0f" else 'False'


def atod(a):
    return struct.unpack("!L", inet_aton(a))[0]


def dtoa(d):
    return inet_ntoa(struct.pack("!L", d))


def OsNameClientVersion(data):
    try:
        if PY2OR3 == "PY3":
            length = struct.unpack('<H', data[43:45].encode('latin-1'))[0]
        else:
            length = struct.unpack('<H', data[43:45])[0]
        if length > 255:
            OsVersion, ClientVersion = tuple([e.replace("\x00", "") for e in data[47+length:].split('\x00\x00\x00')[:2]])
            return OsVersion, ClientVersion
        if length <= 255:
            OsVersion, ClientVersion = tuple([e.replace("\x00", "") for e in data[46+length:].split('\x00\x00\x00')[:2]])
            return OsVersion, ClientVersion
    except Exception:
        return "Could not fingerprint Os version.", "Could not fingerprint LanManager Client version"


def GetHostnameAndDomainName(data):
    try:
        data = NetworkRecvBufferPython2or3(data)
        DomainJoined, Hostname = tuple([e.replace("\x00", "") for e in data[81:].split('\x00\x00\x00')[:2]])
        #If max length domain name, there won't be a \x00\x00\x00 delineator to split on
        if Hostname == '':
            DomainJoined = data[81:110].decode('latin-1')
            Hostname = data[113:].decode('latin-1')
        return Hostname, DomainJoined
    except:
        return "Could not get Hostname.", "Could not get Domain joined"


def DomainGrab(Host):
    global SMB1
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(Timeout)
    try:
        s.connect(Host)
        h = SMBHeaderLanMan(cmd="\x72",mid="\x01\x00",flag1="\x00", flag2="\x00\x00")
        n = SMBNegoDataLanMan()
        packet0 = str(h)+str(n)
        buffer0 = longueur(packet0)+packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(2048)
        s.close()
        if data[8:10] == b'\x72\x00':
            return GetHostnameAndDomainName(data)
    except IOError as e:
        if e.errno == errno.ECONNRESET:
            SMB1 = "False"
        return False


def SmbFinger(Host):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(Timeout)
    try:
        s.connect(Host)
    except:
        # FIXME why?!
        pass

    try:
        h = SMBHeader(cmd="\x72",flag1="\x18",flag2="\x53\xc8")
        n = SMBNego(Data = SMBNegoData())
        n.calculate()
        packet0 = str(h)+str(n)
        buffer0 = longueur(packet0)+packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(2048)
        signing = IsSigningEnabled(data)
        if data[8:10] == b'\x72\x00':
            head = SMBHeader(cmd="\x73",flag1="\x18",flag2="\x17\xc8",uid="\x00\x00")
            t = SMBSessionFingerData()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(NetworkSendBufferPython2or3(buffer1))
            data = s.recv(2048)
        if data[8:10] == b'\x73\x16':
            OsVersion, ClientVersion = OsNameClientVersion(NetworkRecvBufferPython2or3(data))
            return signing, OsVersion, ClientVersion
    except:
        pass


def check_smb_null_session(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(Timeout)
    try:
        s.connect(host)
        h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x53\xc8")
        n = SMBNego(Data = SMBNegoData())
        n.calculate()
        packet0 = str(h)+str(n)
        buffer0 = longueur(packet0)+packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(2048)
        if data[8:10] == b'\x72\x00':
            h = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x17\xc8",mid="\x40\x00")
            n = SMBSessionData()
            n.calculate()
            packet0 = str(h)+str(n)
            buffer0 = longueur(packet0)+packet0
            s.send(NetworkSendBufferPython2or3(buffer0))
            data = s.recv(2048)
        if data[8:10] == b'\x73\x16':
            h = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x17\xc8",uid=data[32:34].decode('latin-1'),mid="\x80\x00")
            n = SMBSession2()
            n.calculate()
            packet0 = str(h)+str(n)
            buffer0 = longueur(packet0)+packet0
            s.send(NetworkSendBufferPython2or3(buffer0))
            data = s.recv(2048)
        if data[8:10] == b'\x73\x00':
            h = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",uid=data[32:34].decode('latin-1'),mid="\xc0\x00")
            n = SMBTreeConnectData()
            n.calculate()
            packet0 = str(h)+str(n)
            buffer0 = longueur(packet0)+packet0
            s.send(NetworkSendBufferPython2or3(buffer0))
            data = s.recv(2048)
        return data[8:10] == b'\x75\x00'
    except Exception:
        return False

##################
#SMB2 part:

def ConnectAndChoseSMB(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(Timeout)
    try:
        s.connect(host)
        h = SMBHeader(cmd="\x72",flag1="\x00")
        n = SMBNego(Data = SMB2NegoData())
        n.calculate()
        packet0 = str(h)+str(n)
        buffer0 = longueur(packet0)+packet0
        s.send(NetworkSendBufferPython2or3(buffer0))
        data = s.recv(4096)
    except:
        return False

    if ParseNegotiateSMB2Ans(data):
        try:
            while True:
                s.send(NetworkSendBufferPython2or3(handle(data.decode('latin-1'), host)))
                data = s.recv(4096)
                if not data:
                    break
        except Exception:
            pass
    else:
        return False
    # FIXME returns None or False, why?!


def handle(data, host):
    if data[28] == "\x00":
        a =  SMBv2Head()
        a.calculate()
        b = SMBv2Negotiate()
        b.calculate()
        packet0 =str(a)+str(b)
        buffer0 = longueur(packet0)+packet0
        return buffer0

    if data[28] == "\x01":
        global Bootime
        SMB2SigningMandatory(data)
        Bootime = IsDCVuln(GetBootTime(data[116:124]), host[0])
        a = SMBv2Head(SMBv2Command="\x01\x00",CommandSequence= "\x02\x00\x00\x00\x00\x00\x00\x00")
        a.calculate()
        b = SMBv2Session1()
        b.calculate()
        packet0 = str(a)+str(b)
        buffer0 = longueur(packet0)+packet0
        return buffer0

    if data[28] == "\x02":
        ParseSMBNTLM2Exchange(data, host[0], Bootime, SMB2signing)


def IsServiceOn(Host):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(Timeout)
    try:
        s.connect(Host)
        return 'True'

    except Exception:
        pass

    return 'False'


##################
def ShowSmallResults(host):
    print(host)
    # FIXME Returns None or False
    # FIXME inverted logic of ConnectAndChose
    if ConnectAndChoseSMB((host, 445)) != False:
        return

    try:
        Hostname, DomainJoined = DomainGrab((host, 445))
        Signing, OsVer, LanManClient = SmbFinger((host, 445))
        NullSess = check_smb_null_session((host, 445))
        RDP = IsServiceOn((host, 3389))
        SQL = IsServiceOn((host, 1433))
        print(("[SMB1]:['{}', Os:'{}', Domain:'{}', Signing:'{}', Null Session: '{}', RDP:'{}', MSSQL:'{}']".format(host, OsVer, DomainJoined, Signing, NullSess,RDP, SQL)))
        SaveToDb({
            'Protocol': '[SMB1]',
            'Host': host,
            'WindowsVersion': OsVer,
            'OsVer': OsVer,
            'DomainJoined': DomainJoined,
            'Bootime': 'N/A', # TODO SQL nil
            'Signing': Signing, # TODO SQL bool
            'NullSess': NullSess,
            'IsRDPOn':RDP,
            'SMB1': 'True', # TODO Real SQL bool
            'MSSQL': SQL
            })
    except Exception:
        return False


# TODO use ipaddress module for subnet address enumeration
def RunFinger(host):
    m = re.search("/", str(host))
    if m:
        net, _, mask = host.partition('/')
        mask = int(mask)
        net = atod(net)
        threads = []
        Pool = multiprocessing.Pool(processes=250)
        func = ShowSmallResults
        for host in [dtoa(net+n) for n in range(0, 1<<32-mask)]:
            proc = Pool.apply_async(func, ((host),))
            threads.append(proc)
        for proc in threads:
            proc.get()
    else:
         ShowSmallResults(Ln)


if Filename != None:
    with open(Filename) as fp:
        for ln in fp.readlines():
            RunFinger(ln.strip())
else:
    RunFinger(Host)
