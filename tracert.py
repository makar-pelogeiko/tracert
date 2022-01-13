import socket
import struct
import random
import select
import argparse
import textwrap
import sys

# ICMP (англ. Internet Control Message Protocol — протокол межсетевых управляющих сообщений) — сетевой протокол,
# входящий в стек протоколов TCP/IP. В основном ICMP используется для передачи сообщений об ошибках и других
# исключительных ситуациях, возникших при передаче данных, например, запрашиваемая услуга недоступна,
# или хост, или маршрутизатор не отвечают

# Код протокола, используемый в функции socket (7 для ICMP, 6 для TCP, 17 для UDP)
# [https://pythontic.com/modules/socket/getprotobyname]
ICMP_CODE = socket.getprotobyname('icmp')
UDP_CODE = socket.getprotobyname('udp')
# Константа, кодирующая тип ICMP запроса. 8 - Echo Request (требование эха) [http://ping-test.ru/icmp]
ICMP_ECHO_REQUEST = 8
# Случайный порт отправки
port = 10_000 + int(32567 * random.random())

def trace_udp(dest_addr, ttl, timeout, print_errors: bool):
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_socket.bind(("", 1))

    address = None
    address_name = None

    try:
        # Отправка пакета
        send_socket.sendto(bytes('hello', "utf-8"), (dest_addr, port))

        # Ожидание ответа
        ready = select.select([recv_socket], [], [], timeout)

    except socket.error:
        if print_errors:
            print("socket error occurred in Main query")

    # Время ожидания истекло, ответ не пришел
    if ready[0] == []:
        address = '*'
        address_name = address
    else:
        _, address = recv_socket.recvfrom(512)
        address = address[0]
        try:
            address_name = socket.gethostbyaddr(address)[0]
        except socket.error:
            if print_errors:
                print("socket error occurred in DNS")
            address_name = address

    send_socket.close()
    recv_socket.close()

    return address, address_name

# Выполнение единичного 'ping' запроса по сервисному протоколу ICMP
def trace_icmp(destination, ttl, timeout, print_errors: bool):
    def checksum_calc(source_string):
        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0

        while count < count_to:
            this_val = (source_string[count + 1]) * 256 + (source_string[count])
            sum = sum + this_val
            sum = sum & 0xffffffff
            count = count + 2

        if count_to < len(source_string):
            sum = sum + (source_string[len(source_string) - 1])
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        # Swap bytes
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # --------- Конфигурация ICMP пакета ---------
    # Структура пакета: [https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/]
    id = int(random.random() * 32000)
    checksum = checksum_calc(struct.pack('BBHHH', ICMP_ECHO_REQUEST, 0, 0, id, 1))
    packet = struct.pack('BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(checksum), id, 1)
    # --------------------------------------------

    try:
        # Отправка пакета
        my_socket.sendto(packet, (destination, port))

        # Ожидание ответа
        ready = select.select([my_socket], [], [], timeout)
    except socket.error:
        if (print_errors):
            print("socket error occurred in Main query")

    # Время ожидания истекло, ответ не пришел
    if ready[0] == []:
        my_socket.close()
        return '*', '*'

    _, address = my_socket.recvfrom(1024)
    address = address[0]

    my_socket.close()

    try:
        address_name = socket.gethostbyaddr(address)[0]
    except socket.error:
        address_name = address
        if print_errors:
            print("socket error occurred in DNS")

    return address, address_name

def main(dest_ip, timeout: int=1, max_steps :int=32, t_type: str='icmp', print_errors: bool=False):
    trace_funcs = {'icmp': trace_icmp, 'udp': trace_udp}
    print(f"Start tracing ip: {dest_ip}, protocol: {t_type}, timeout: {timeout}, max steps: {max_steps}, port: {port}")

    for i, ttl in enumerate(range(1, max_steps + 1)):
        answ, answ_name = trace_funcs[t_type](dest_ip, ttl, timeout, print_errors)
        if answ == answ_name:
            print(f"{i}. {answ}")
        else:
            print(f"{i}. {answ} ({answ_name})")

        if (answ == dest_ip):
            print('Reached ')
            break

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        parser = argparse.ArgumentParser(
            prog='tracertUtil',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''\
                 about program:
                     This program shows ip trace between
                     this ip and given ip
                 '''))
        parser.add_argument('destination', help='ip_v4 such as 192.168.43.30 address or domen such as google.com')
        parser.add_argument(
            "--timeout",
            help="timeout as int number in seconds",
            type=int,
        )
        parser.add_argument(
            "--t_type",
            help="icmp - use ICMP protocol\n\
                  udp - use UDP protocol",
            type=str,
        )
        parser.add_argument(
            "--max_steps",
            help="max ips on the way int number",
            type=int,
        )

        args = parser.parse_args()

        if args.timeout is not None:
            if type(args.timeout) is not int or args.timeout < 0:
                args.timeout = 1
        else:
            args.timeout = 1

        if args.max_steps is not None:
            if type(args.max_steps) is not int or args.max_steps < 0:
                args.max_steps = 32
        else:
            args.max_steps = 32

        if args.t_type is not None:
            if args.t_type not in ['icmp', 'udp']:
                args.t_type = 'icmp'
        else:
            args.t_type = 'icmp'

        main(args.destination, args.timeout, args.max_steps, args.t_type)
    else:
        destination = input('Destination: ')
        # Превращает имя[str] в IP[str]
        dest_ip = socket.gethostbyname(destination)
        print('Destinantion: ' + destination + ' ' + dest_ip)
        main(dest_ip)
