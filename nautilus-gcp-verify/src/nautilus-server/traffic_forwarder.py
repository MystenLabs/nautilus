# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
A bidirectional network traffic forwarder that bridges TCP/IP and VSOCK sockets, enabling communication
between host machines and enclaves.
Referenced from https://github.com/aws-samples/aws-nitro-enclaves-workshop/blob/main/resources/code/my-first-enclave/secure-local-channel/traffic_forwarder.py
"""

import socket
import sys
import threading
import time


def server(local_ip, local_port, remote_cid, remote_port):
    try:
        dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dock_socket.bind((local_ip, local_port))
        dock_socket.listen(5)

        while True:
            client_socket = dock_socket.accept()[0]

            server_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            server_socket.connect((remote_cid, remote_port))

            outgoing_thread = threading.Thread(target=forward,
                                               args=(client_socket,
                                                     server_socket))
            incoming_thread = threading.Thread(target=forward,
                                               args=(server_socket,
                                                     client_socket))

            outgoing_thread.start()
            incoming_thread.start()
    finally:
        new_thread = threading.Thread(target=server,
                                      args=(local_ip, local_port, remote_cid,
                                            remote_port))
        new_thread.start()

    return


def forward(source, destination):
    string = ' '
    while string:
        try:
            string = source.recv(1024)
            if string:
                destination.sendall(string)
            else:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR)
        except ConnectionResetError as e:
            print(f"[WARN] Connection reset by peer: {e}")
            source.close()
            destination.close()
            break
        except Exception as e:
            # Catch-all for any other unexpected exceptions
            print(f"[ERROR] Unexpected socket exception: {e}")
            source.close()
            destination.close()
            break


def main(args):
    local_ip = str(args[0])
    local_port = int(args[1])
    remote_cid = int(args[2])
    remote_port = int(args[3])

    thread = threading.Thread(target=server,
                              args=(local_ip, local_port, remote_cid,
                                    remote_port))
    thread.start()
    print(
        f"starting forwarder on {local_ip}:{local_port} {remote_cid}:{remote_port}"
    )
    while True:
        time.sleep(60)


if __name__ == '__main__':
    main(sys.argv[1:])
