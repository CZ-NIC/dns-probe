#!/usr/bin/env python3

import os
import socket
import ssl
import threading
import argparse
import struct

def handle_conn(conn):
    print("New client")
    try:
        flength = conn.recv(1)
        if not flength:
            raise Exception("No filename length data")

        output = conn.recv(struct.unpack('B', flength)[0])
        if not output:
            raise Exception("No filename data")
    except:
        conn.close()
        raise

    output = output.decode()
    f = open(output + ".part", "wb")

    try:
        while True:
            data = conn.recv(4096)
            if data:
                f.write(data)
            else:
                break
    except ConnectionResetError:
        print("Connection Reset Error")
        pass
    finally:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        f.close()
        os.rename(output + ".part", output)


if __name__ == "__main__":
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", dest="SERVER_CERT", help="Server certificate", required=True)
    parser.add_argument("-k", dest="SERVER_KEY", help="Server private key", required=True)
    parser.add_argument("-c", dest="CLIENT_CERT", help="Client certificate")
    parser.add_argument("-a", dest="IP", default='127.0.0.1', help="Server IP address (default: 127.0.0.1)")
    parser.add_argument("-p", dest="PORT", default=6378, help="Server port to listen on (default: 6378)")
    args = parser.parse_args()

    print("Server cert: ", args.SERVER_CERT)
    print("Server key: ", args.SERVER_KEY)
    print("Client cert: ", args.CLIENT_CERT)
    print("Server IP: ", args.IP)
    print("Server port: ", args.PORT)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    if args.CLIENT_CERT:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=args.CLIENT_CERT)
    else:
        context.verify_mode = ssl.CERT_NONE

    if args.SERVER_CERT and args.SERVER_KEY:
        context.load_cert_chain(certfile=args.SERVER_CERT, keyfile=args.SERVER_KEY)
    else:
        context.load_default_certs()

    bindsocket = socket.socket()
    bindsocket.bind((args.IP, args.PORT))
    bindsocket.listen(5)

    try:
        while True:
            print("Waiting...")
            newsocket, fromaddr = bindsocket.accept()
            connstream = context.wrap_socket(newsocket, server_side=True)
            threading.Thread(target=handle_conn, args=(connstream,)).start()
    except KeyboardInterrupt:
        print("Ending on KeyboardInterrupt")
    except:
        print("Ending")
    finally:
        bindsocket.close()
