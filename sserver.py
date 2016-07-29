#!/usr/bin/python3
import argparse
import logging
import select
import socket
import sys
import threading


# global log message formatter
g_log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')


# get "standard" logger for application, public api
def createlogger(name, debug=False):
    level = logging.INFO
    if debug:
        level = logging.DEBUG
    # each module gets its own logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    # each module logger has its own handler attached
    log_handler = logging.StreamHandler(stream=sys.stdout)
    log_handler.setLevel(level)
    # but all loggers/handlers have the same global formatter
    log_handler.setFormatter(g_log_formatter)
    logger.addHandler(log_handler)
    return logger


g_logger = createlogger(__name__, debug=True)


def myhex(num) -> str:
    s = hex(num).replace('0x', '')  # remove '0x' in front
    if (len(s) == 1) or (len(s) == 3):  # prepend leading zero
        s = '0' + s
    return s


def mysend_fully(sock: socket.socket, msg: bytes):
    totalsent = 0
    msglen = len(msg)
    while totalsent < msglen:
        # wait until ready to send (10 seconds)
        rrcv, rsnd, rerr = select.select([], [sock], [], 10)
        if sock not in rsnd:  # still not ready to send!
            return False
        # send what we can...
        nsent = sock.send(msg[totalsent:])
        if nsent == 0:
            # raise RuntimeError("socket connection broken")
            return False
        totalsent = totalsent + nsent
    return True


class Socks5Const:
    AUTH_METHOD_NO_AUTHENTICATION_REQUIRED = b'\x00'
    AUTH_METHOD_GSSAPI = b'\x01'
    AUTH_METHOD_USERNAME_PASSWORD = b'\x02'
    AUTH_METHOD_NO_ACCEPTABLE_METHODS = b'\xFF'
    # '\x03' to '\x7F' IANA ASSIGNED
    # '\x80' to '\xFE' RESERVED FOR PRIVATE METHODS

    CMD_CONNECT = b'\x01'
    CMD_BIND = b'\x02'
    CMD_UDP_ASSOCIATE = b'\x03'

    ATYPE_IPV4 = b'\x01'
    ATYPE_DOMAINNAME = b'\x03'
    ATYPE_IPV6 = b'\x04'

    REP_OK = b'\x00'                       # succeeded
    REP_FAILURE = b'\x01'                  # general SOCKS server failure
    REP_NOT_ALLOWED = b'\x02'              # connection not allowed by ruleset
    REP_NETWORK_UNREACHABLE = b'\x03'      # Network unreachable
    REP_HOST_UNREACHABLE = b'\x04'         # Host unreachable
    REP_CONN_REFUSED = b'\x05'             # Connection refused
    REP_TTL_EXPIRED = b'\x06'              # TTL expired
    REP_CMD_NOT_SUPPORTED = b'\x07'        # Command not supported
    REP_ADDR_TYPE_NOT_SUPPORTED = b'\x08'  # Address type not supported
    # '\x09' to '\xFF' unassigned


class SocksClientException(RuntimeError):
    def __init__(self, message):
        super(SocksClientException, self).__init__()
        self.message = message


class SocksClientThread(threading.Thread):
    def __init__(self, client_sock: socket.socket, client_address: tuple, daemon=None):
        super(SocksClientThread, self).__init__(daemon=daemon)
        self.client_sock = client_sock
        self.client_address = client_address
        client_name = str(client_address[0]) + ':' + str(client_address[1])
        self.logger = createlogger('client [{0}]'.format(client_name), debug=True)
        self.dest_addr = ('0.0.0.0', 0)
        self.remote_sock = None

    def run(self):
        self.logger.info('Started thread for client {0}'.format(self.client_address))
        try:
            # step 1. client connects and sends its auth methods supported
            self.receive_client_methods()
            # step 2. after successful auth client sends request to proxy
            self.receive_client_request()
            # step 3. client may send data to server, server can reply..
            self.loop_send_recv()
        except SocksClientException as sce:
            self.logger.error('Error during client processing: {0}'.format(sce.message))
        # in the very end, close accepted client socket
        self.client_sock.shutdown(socket.SHUT_RDWR)
        self.client_sock.close()
        # .. aand close remote socket
        if self.remote_sock is not None:
            self.remote_sock.shutdown(socket.SHUT_RDWR)
            self.remote_sock.close()

    def recv_socks_version(self):
        b = self.client_sock.recv(1)  # protocol version, 1 byte
        socks_version = int(b[0])
        if socks_version != 5:
            self.reply_method_selection(Socks5Const.AUTH_METHOD_NO_ACCEPTABLE_METHODS)
            raise SocksClientException('Invalid SOCKS version from client!')

    def recv_ipv4_addr(self):
        b4 = self.client_sock.recv(4)
        return b4

    def recv_hostname(self) -> str:
        hn_len = self.client_sock.recv(1)
        ihn_len = int(hn_len[0])
        hn = self.client_sock.recv(ihn_len)
        return hn.decode(encoding='utf-8')

    def recv_ipv6_addr(self):
        b16 = self.client_sock.recv(16)
        return b16

    def recv_port(self) -> int:
        b2 = self.client_sock.recv(2)
        b = list(b2)  # convert to list of integers
        port = b[0]*256 + b[1]  # [1, 187] => 1*256 + 187 = 443
        return port

    def receive_client_methods(self):
        # The client connects to the server, and sends a version
        # identifier/method selection message:
        #           +----+----------+----------+
        #           |VER | NMETHODS | METHODS  |
        #           +----+----------+----------+
        #           | 1  |    1     | 1 to 255 |
        #           +----+----------+----------+
        self.recv_socks_version()
        b = self.client_sock.recv(1)  # nmethods, 1 byte
        nmethods = int(b[0])
        # self.logger.debug('Received hello, Nmethods={0}'.format(nmethods))
        req_methods = []
        for i in range(0, nmethods):
            b = self.client_sock.recv(1)
            req_methods.append(b)
        # self.logger.debug('Requested methods: {0}'.format(req_methods))
        #
        if Socks5Const.AUTH_METHOD_NO_AUTHENTICATION_REQUIRED not in req_methods:
            self.reply_method_selection(Socks5Const.AUTH_METHOD_NO_ACCEPTABLE_METHODS)
            raise SocksClientException('Client requests unsupported auth methods!')
        self.reply_method_selection(Socks5Const.AUTH_METHOD_NO_AUTHENTICATION_REQUIRED)

    def reply_method_selection(self, method_code):
        # The server selects from one of the methods given in METHODS, and
        # sends a METHOD selection message:
        #                 +----+--------+
        #                 |VER | METHOD |
        #                 +----+--------+
        #                 | 1  |   1    |
        #                 +----+--------+
        # If the selected METHOD is X'FF', none of the methods listed by the
        # client are acceptable, and the client MUST close the connection.
        # The values currently defined for METHOD are:
        #    X'00' NO AUTHENTICATION REQUIRED
        #    X'01' GSSAPI
        #    X'02' USERNAME/PASSWORD
        #    X'03' to X'7F' IANA ASSIGNED
        #    X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        #    X'FF' NO ACCEPTABLE METHODS
        data = b'\x05' + method_code
        self.client_sock.send(data)

    def receive_client_request(self):
        # The SOCKS request is formed as follows:
        # +-----+-----+-------+------+----------+----------+
        # | VER | CMD | RSV   | ATYP | DST.ADDR | DST.PORT |
        # +-----+-----+-------+------+----------+----------+
        # | 1   | 1  | X '00' | 1   | Variable | 2        |
        # +----+-----+-------+------+----------+----------+
        # Where:
        #    o VER protocol version: X'05'
        #    o CMD
        #       o CONNECT X'01'
        #       o BIND X'02'
        #       o UDP ASSOCIATE '03'
        #    o RSV RESERVED
        #    o ATYP address type of following address
        #       o IPV4 address: X'01'
        #       o DOMAINNAME: X'03'
        #       o IPV6 address: X'04'
        #    o DST.ADDR desired destination address
        #    o DST.PORT desired destination port in network octet order
        self.recv_socks_version()       # socks ver
        cmd = self.client_sock.recv(1)  # cmd
        self.client_sock.recv(1)        # rzv
        atyp = self.client_sock.recv(1)
        self.logger.debug('  Cmd: {0}, atype {1}'.format(cmd, atyp))
        if cmd != Socks5Const.CMD_CONNECT:
            self.reply_client_request_err(Socks5Const.REP_CMD_NOT_SUPPORTED)
            raise SocksClientException('Unknown command: {0}'.format(cmd))
        dest_addr = b''
        if atyp == Socks5Const.ATYPE_IPV4:
            dest_addr = self.recv_ipv4_addr()
        elif atyp == Socks5Const.ATYPE_DOMAINNAME:
            dest_addr = self.recv_hostname()
        else:  # all other address type are unhandled :(
            self.reply_client_request_err(Socks5Const.REP_ADDR_TYPE_NOT_SUPPORTED)
            raise SocksClientException('Unknown address type: {0}'.format(atyp))
        dest_port = self.recv_port()
        self.dest_addr = (dest_addr, dest_port)
        self.logger.debug('  dest_addr: {0}'.format(self.dest_addr))
        #
        # TODO: place for check that destination address is allowed
        #
        # try to connect to specified dest
        if self.remote_sock is not None:
            self.remote_sock.close()
        try:
            self.logger.debug(' ... Connecting to: {0}...'.format(self.dest_addr))
            self.remote_sock = socket.create_connection(self.dest_addr, timeout=10)
        except socket.timeout:
            self.reply_client_request_err(Socks5Const.REP_CONN_REFUSED)
            raise SocksClientException('Dest addr {0} connect timeout!'.format(self.dest_addr))
        except socket.gaierror:
            self.reply_client_request_err(Socks5Const.REP_HOST_UNREACHABLE)
            raise SocksClientException('Cannot resolve hostname: {0}!'.format(self.dest_addr[0]))
        # everyting goes fine, we have connection to requested host
        # notify client that all OK, we need or remote socket local address
        rsock_addr = self.remote_sock.getsockname()
        # self.logger.debug('  Got remote socket local address: {0}'.format(rsock_addr))
        #  Got remote socket local address: ('192.168.20.2', 6570)
        rsock_addr_ip = socket.inet_aton(rsock_addr[0])  # converts IP to bytes representation
        # ^^ socket.inet_aton('127.0.0.1')  =>  b'\x7f\x00\x00\x01'
        local_port = rsock_addr[1]  # port as integer
        rsock_port = bytes.fromhex(myhex(local_port // 256) +  # higher byte
                                   myhex(local_port % 256))    # lower byte
        self.reply_client_request(Socks5Const.REP_OK, Socks5Const.ATYPE_IPV4,
                                  rsock_addr_ip, rsock_port)
        self.logger.info('  Successfully created proxy connection to {0}.'.format(self.dest_addr))

    def reply_client_request_err(self, rep_err_code: bytes):
        self.reply_client_request(rep_err_code, Socks5Const.ATYPE_IPV4, b'\x00\x00\x00\x00', b'\x00\x00')

    def reply_client_request(self, rep_code: bytes, atyp: bytes, bnd_addr: bytes, bnd_port: bytes):
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        # | 1  |  1  | X'00' |  1   | Variable |    2     |
        # +----+-----+-------+------+----------+----------+
        #  o  VER    protocol version: X'05'
        #  o  REP    Reply field:
        #     o  X'00' succeeded
        #     o  X'01' general SOCKS server failure
        #     o  X'02' connection not allowed by ruleset
        #     o  X'03' Network unreachable
        #     o  X'04' Host unreachable
        #     o  X'05' Connection refused
        #     o  X'06' TTL expired
        #     o  X'07' Command not supported
        #     o  X'08' Address type not supported
        #     o  X'09' to X'FF' unassigned
        #  o  RSV    RESERVED
        #  o  ATYP   address type of following address
        #     o  IP V4 address: X'01'
        #     o  DOMAINNAME: X'03'
        #     o  IP V6 address: X'04'
        #  o  BND.ADDR       server bound address
        #  o  BND.PORT       server bound port in network octet order
        #
        # Fields marked RESERVED (RSV) must be set to X'00'.
        r = b'\x05'    # socks version
        r += rep_code
        r += b'\x00'   # rzv
        r += atyp
        r += bnd_addr
        r += bnd_port
        self.client_sock.send(r)

    def loop_send_recv(self):
        # 1) put all sockets in non-blocking mode
        self.client_sock.settimeout(0)
        self.remote_sock.settimeout(0)
        # 2) lists fro select()
        rcvlist = [self.client_sock, self.remote_sock]
        sndlist = [self.client_sock, self.remote_sock]
        # 3) select() loop
        have_error = False
        while not have_error:
            rrcv, rsnd, rerr = select.select(rcvlist, sndlist, [], 10)
            if self.client_sock in rrcv:
                self.logger.debug('    Client socket is ready for reading!')
                inp = self.client_sock.recv(4096)
                if inp == b'':  # received 0 length = connection closed
                    have_error = True
                    self.logger.debug('    Client has closed the connection!')
                else:
                    if not mysend_fully(self.remote_sock, inp):
                        # sending failed!
                        have_error = True
                        self.logger.warn('    Could not resend {0} bytes from client '
                                         'to server!'.format(len(inp)))
            if self.remote_sock in rrcv:
                self.logger.debug('    Remote socket is ready for reading!')
                inp = self.remote_sock.recv(4096)
                if inp == b'':  # received 0 length = connection closed
                    have_error = True
                    self.logger.debug('    Remote host has closed the connection!')
                else:
                    if not mysend_fully(self.client_sock, inp):
                        # sending failed!
                        have_error = True
                        self.logger.warn('    Could not resend {0} bytes from remote server '
                                         'to client!'.format(len(inp)))
        self.logger.debug('  Ending receive/send loop!')


class SocksServer:

    opts = {}
    logger = None
    sock = None

    def __init__(self):
        self.opts['port'] = 1080
        self.address = ('0.0.0.0', 1080)
        self.allowed_ips = []
        self.should_exit = False

    def parse_args(self) -> bool:
        ap = argparse.ArgumentParser(description='Socks5 proxy server. It can be configured only through '
                                                 'command-line parameters.')
        ap.add_argument('--version', action='version', version='%(prog)s v0.1')
        ap.add_argument('--debug', action='store_true', help='Enable debug output.')
        ap.add_argument('--port', nargs='?', default='1080', type=int, metavar='LISTEN_PORT',
                        help='Port to listen on. Default for SOCKS: 1080')
        ap.add_argument('--allow-ips', nargs='?', default='', type=str, metavar='ALLOWED_IPS',
                        help='Accept connections only from specified IP addresses '
                        'Example: 192.168.20.1,127.0.0.1 '
                        '(Default is empty, accept from all)')
        ns = ap.parse_args()
        # apply parse results
        self.opts['port'] = ns.port
        if ns.allow_ips != '':
            self.allowed_ips = ns.allow_ips.split(',')
        self.logger = createlogger('sockserver', debug=ns.debug)
        #
        self.logger.debug('SocksServer configured, port = {0}'.format(self.opts['port']))
        self.logger.debug('  allowed IPs: {0}'.format(self.allowed_ips))
        return True

    def start(self):
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        self.address = ('0.0.0.0', self.opts['port'])
        self.sock.bind(self.address)
        self.sock.listen(1)
        self.sock.settimeout(1)  # 1 sec
        self.logger.info('Listening at {0}'.format(self.address))
        while not self.should_exit:
            try:
                client_sock, client_address = self.sock.accept()
                is_allowed = True
                if len(self.allowed_ips) > 0:
                    # check allowed IP
                    client_ip = client_address[0]
                    if client_ip not in self.allowed_ips:
                        self.logger.warn('Client IP was denied: {0}; not in allowed list.'.format(client_ip))
                        is_allowed = False
                if is_allowed:
                    # process client
                    self.logger.info('Accepted client: {0}'.format(client_address))
                    # by default accepted client socket inherits listening socket timeout settings
                    # reset it to default
                    client_sock.settimeout(None)  # blocking mode
                    sct = SocksClientThread(client_sock, client_address, daemon=True)
                    sct.start()
                else:
                    # just close client socket
                    client_sock.shutdown(socket.SHUT_RDWR)
                    client_sock.close()
            except socket.timeout:
                pass
        self.logger.info('Ended accept() loop, exiting!')
        # close server socket
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.sock = None


def main():
    g_logger.info('In main')
    ss = SocksServer()
    if ss.parse_args():
        ss.start()

if __name__ == '__main__':
    main()
