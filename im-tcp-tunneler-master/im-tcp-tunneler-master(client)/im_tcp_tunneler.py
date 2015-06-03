# -*- coding:cp936 -*-
# from wsgiref.simple_server import make_server
# import urlparse
import threading
import time
#获取ID库
import uuid
#异常库
import traceback
import socket
import struct
import pprint

try:
    #数字签名
    import gnupg
    from M2Crypto import EVP, Rand
except ImportError:
    gnupg = None
    gpg = None

PROMPT = object()
AGENT = object()
    
exposed = {
    # 'IP:PORT': ['JID', ...], ...
    }

forwarded = [
    # 'IP:PORT->IP:PORT!JID', ...
    ]

gpg_keys = [
    # 'JID' or ('JID', 'keyid'), ...
    ]

gpg_passphrase = None

encryption_is_strict = True # set this to False to allow combination of encrypted and unencrypted connections

web_port = None

DBG1 = 0
DBG2 = 0

BUFFERING = 1
#未安装PYXMPP函数实现异常处理
def send_xmpp_message(from_jid, to_jid, body): raise NotImplemented
def get_client_jid(): raise NotImplemented

# def web_app(environ, start_response):
#     q = urlparse.parse_qs(environ['QUERY_STRING'])

#     if '/test' in environ['PATH_INFO']:
#         start_response('200 OK', [('Content-Type', 'text/html')])
#         return ['OK: %s\n' % time.asctime()]

#     else:
#         start_response('404 Not Found', [('Content-Type', 'text/plain')])
#         return ['Not Found\n']
#线程类
class Connection:
    def __init__(self):
        #生成唯一ID
        self.id = str(uuid.uuid4())
        self.sock = None
        self.encipher = None
        self.decipher = None
        self.buffer = ''
        self.bufsize = 15000
    def __repr__(self):
        return '%s(id=%r, remote_jid=%r)' % (self.__class__.__name__, self.id, self.remote_jid)
    
conns = {}

def get_num_of_connections():
    with lock: return len(conns)
#线程锁
lock = threading.RLock()
#创建监听函数  sock服务器端
def s2x_socket_listener((src_addr, src_port), (dst_addr, dst_port), dst_jid):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #绑定端口
    sock.bind((src_addr, src_port))
    #指定多少个客户端连接到服务器
    sock.listen(5)
    while 1:
        #等待客户端请求一个链接
        conn, addr = sock.accept()
        if DBG1:
            print 's2x_socket_listener(%s:%d->%s:%d!%s), accepted: %r' % (
                src_addr, src_port, dst_addr, dst_port, dst_jid, (conn, addr))
        c = Connection()
        c.sock = conn
        c.remote_jid = dst_jid
        with lock:
            conns[c.id] = c
            if DBG2: print conns
        #加密处理
        if get_jid_keyid(c.remote_jid):
            print 'im_tcp_tunneler: connection to %s:%d!%s ENCRYPTED' % (dst_addr, dst_port, dst_jid)
            enkey = Rand.rand_bytes(64)
            c.encipher = EVP.Cipher(alg='aes_256_cbc', key=enkey[0:32], iv=enkey[32:64], op=1, padding=0)
            ek = encode(encrypt_gpg(c.remote_jid, enkey))
        else:
            ek = '-'
        #通过XMPP发送数据
        send_xmpp_message(get_client_jid(), c.remote_jid,
                          'CONNECT %s:%d %s %s' % (dst_addr, dst_port, c.id, ek))
        #创建数据接收线程
        t = threading.Thread(target=connection_handler, args=(c,))
        #创建守护进程
        t.setDaemon(True)
        t.start()
#sock 数据接收  服务器接收
def connection_handler(c):
    def send_data(data):
        if c.encipher:
            #网络传输字节码打包struct.pack
            data = struct.pack('!I', len(data)) + data
            if len(data)%16 > 0: data += Rand.rand_bytes(16 - (len(data)%16))
            data = c.encipher.update(data)+c.encipher.final()
        send_xmpp_message(get_client_jid(), c.remote_jid,
                          'DATA %s %s' % (c.id, encode(data)))
    #设置超时
    if BUFFERING: c.sock.settimeout(0.01)
    else:         c.sock.settimeout(0.3)
    while 1:
        #接收数据
        try: d = c.sock.recv(1024)
        except socket.timeout:
            #if DBG2: print 'socket.timeout', c.id
            if BUFFERING:
                # flush
                if c.buffer:
                    d = c.buffer; c.buffer = ''
                    send_data(d)
            continue
        except socket.error:
            if DBG1: traceback.print_exc()
            break
        if DBG2: print 'd: %r' % d
        if not d: break
        if not BUFFERING:
            send_data(d)
        else:
            c.buffer += d
            if len(c.buffer) > c.bufsize:
                d = c.buffer[0:c.bufsize]
                c.buffer = c.buffer[c.bufsize:]
                send_data(d)
    try:
        c.sock.close()
        c.sock.recv(1024)
    except socket.error:
        if DBG1: traceback.print_exc()
    with lock:
        if c.id in conns:
            del conns[c.id]
            if DBG2: print 'del conns[%r]' % c.id
        if DBG2: print conns
    if BUFFERING:
        # flush
        d = c.buffer; c.buffer = ''
        send_data(d)
    send_xmpp_message(get_client_jid(), c.remote_jid,
                      'CLOSE %s' % (c.id))
#将IP和端口号分离出来
def parse_addr_port(addr_port):
    addr, port = addr_port.split(':')
    port = int(port)
    return addr, port
 #创建端口监听
def setup_accept_and_forward():
    # accept local connections and forward them to remote tunneler
    #创建监听进程
    for s in forwarded:
        src_addr_port, dst = s.split('->')
        dst_addr_port, dst_jid = dst.split('!')
        t = threading.Thread(target=s2x_socket_listener, args=(
                parse_addr_port(src_addr_port),
                parse_addr_port(dst_addr_port), dst_jid))
        t.setDaemon(True)
        t.start()
#XMPP数据接收相应
def handle_message(from_jid, to_jid, body):
    try:
        resp = None
        if 0:
            print 'handle_message: %s->%s, %r' % (from_jid, to_jid, body[0:])
        print body
        #连接初始化
        if body.startswith('CONNECT '):
            _, addr_port, conn_id, ek = body.split(' ')
            from_jid_norecource , _ = from_jid.split('/') # no need to specify the Recource in .conf files, or if not then no error occur

            c = Connection()
            c.id = conn_id # needed in line 216 if errors occur
            #创建SOCK  exposed服务器端
            if addr_port in exposed and ('*' in exposed[addr_port] or from_jid in exposed[addr_port] or from_jid_norecource in exposed[addr_port]): # also chek if jid without Recource is in .conf
                print 'im_tcp_tunneler: connection allowed for %s to %s' % (from_jid, addr_port)
                addr, port = addr_port.split(':')
                port = int(port)

                
                c.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.sock.connect((addr, port))
                c.remote_jid = from_jid
                #密匙处理
                if get_jid_keyid(c.remote_jid):
                    print 'im_tcp_tunneler: connection from %s to %s ENCRYPTED' % (from_jid, addr_port)
                    dekey = decrypt_gpg(c.remote_jid, decode(ek))
                    c.decipher = EVP.Cipher(alg='aes_256_cbc', key=dekey[0:32], iv=dekey[32:64], op=0, padding=0)
                    enkey = Rand.rand_bytes(64)
                    c.encipher = EVP.Cipher(alg='aes_256_cbc', key=enkey[0:32], iv=enkey[32:64], op=1, padding=0)
                    ek2 = encode(encrypt_gpg(c.remote_jid, enkey))
                else:
                    ek2 = '-'

                with lock:
                    conns[c.id] = c
                    if DBG2: print conns
                #创建线程
                t = threading.Thread(target=connection_handler, args=(c,))
                t.setDaemon(True)
                t.start()

                resp = 'CONNECT_RESULT %s OK %s' % (c.id, ek2)

            else:
                if DBG1:
                    print 'im_tcp_tunneler: connection refused for %s to %s' % (from_jid, addr_port) #useful for debugging which adress gets refused
                resp = 'CONNECT_RESULT %s ERROR -' % c.id
        #重新连接
        elif body.startswith('CONNECT_RESULT '):
            _, conn_id, status, ek = body.split(' ')

            with lock:
                c = conns.get(conn_id, None)
                if DBG2: print conns
            if c:
                if status == 'OK':
                    if get_jid_keyid(c.remote_jid):
                        dekey = decrypt_gpg(c.remote_jid, decode(ek))
                        c.decipher = EVP.Cipher(alg='aes_256_cbc', key=dekey[0:32], iv=dekey[32:64], op=0, padding=0)
                else:
                    c.sock.close()
                    if DBG2: print 'sock.close:', c
        #关闭链接
        elif body.startswith('CLOSE '):
            _, conn_id = body.split()
            with lock:
                c = conns.get(conn_id, None)
                if DBG2: print conns
            if c:
                c.sock.close()
                if DBG2: print 'sock.close:', c
         #数据
        elif body.startswith('DATA '):
            a = body.find(' ')+1
            b = body.find(' ', a)
            conn_id = body[a:b]
            data = body[b+1:]
            with lock:
                c = conns.get(conn_id, None)
                if DBG2: print conns
            if c:
                data = decode(data)
                if c.decipher:
                    data = c.decipher.update(data)+c.decipher.final()
                    hsz = struct.calcsize('!I')
                    #struct.unpack网络传输字节码解包  suruct结构体
                    size, = struct.unpack('!I', data[0:hsz])
                    data = data[hsz:hsz+size]
                    print data
                if DBG2: print 'data: %r' % data
                #SOCK发送数据
                c.sock.send(data)
                #time.sleep(0.01)
                # resp = 'DATA_RESULT %s OK' % conn_id
            else:
                resp = 'DATA_RESULT %s ERROR unknown connection id' % conn_id

        if resp is not None:
            send_xmpp_message(to_jid, from_jid, resp)
        else:
            #发送测试
           # send_xmpp_message(to_jid, from_jid, 'ACK')
            pass
    except:
        #异常处理
        traceback.print_exc()
   #发送数据
   # send_xmpp_message(to_jid, from_jid, 'OK')
   #获取本机JID
   # print get_client_jid()
"""读取配置文档 """
def setup_tunnels(filename):
    ns = {}
    execfile(filename, ns)

    globals().update(ns)
    #加密
    if gpg_keys:
        global gpg, gpg_passphrase
        if gpg_passphrase == PROMPT:
            import getpass
            gpg_passphrase = getpass.getpass('GPG passphrase: ')
        if gpg_passphrase == AGENT:
            gpg = gnupg.GPG(use_agent=True)
            gpg_passphrase = None
        else:
            gpg = gnupg.GPG()
    #创建监听
    setup_accept_and_forward()

    # if web_port is not None:
    #     httpd = make_server('', web_port, web_app)
    #     t = threading.Thread(target=httpd.serve_forever)
    #     t.setDaemon(True)
    #     t.start()


    return ns

data_coding_mode = 'hex' # for xmpp

def encode(data):
    if data_coding_mode == 'hex':
        return data.encode('hex')
    elif data_coding_mode == 'raw':
        return data
    else:
        #异常处理
        raise RuntimeError('unknown coding %r' % data_coding_mode)

def decode(data):
    if data_coding_mode == 'hex':
        return data.decode('hex')
    elif data_coding_mode == 'raw':
        return data
    else:
        raise RuntimeError('unknown coding %r' % data_coding_mode)
#获取JID对应加密密匙
def get_jid_keyid(jid):
    for k in gpg_keys:
        if isinstance(k, str) and k == jid:
            return jid
        elif isinstance(k, tuple) and k[0] == jid:
            return k[1]
    else:
        return None
    if encryption_is_strict:
        raise RuntimeError('no key for %r' % jid)
    else:
        return None
#加密
def _encrypt_gpg(to_jid, data):
    pub_keys = gpg.list_keys()
    keyfps = [k['fingerprint'] for k in pub_keys if ('<%s>' % to_jid) in str(k['uids'])]
    if not keyfps: raise RuntimeError('unknown gpg key')
    if len(keyfps) != 1: raise RuntimeError('more then one pub keys found')
    d = gpg.encrypt(data, keyfps[0], always_trust=True, armor=True)
    return d.data

def _decrypt_gpg(from_jid, data):
    d = gpg.decrypt(data, always_trust=True, passphrase=gpg_passphrase)
    return d.data

def encrypt_gpg(jid, data):
    keyid = get_jid_keyid(jid)
    if keyid: data = _encrypt_gpg(keyid, data)
    elif encryption_is_strict: raise RuntimeError('unencrypted connections are not allowed')
    return data

def decrypt_gpg(jid, data):
    keyid = get_jid_keyid(jid)
    if keyid: data = _decrypt_gpg(keyid, data)
    elif encryption_is_strict: raise RuntimeError('unencrypted connections are not allowed')
    return data

