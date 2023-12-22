import sys
import serial
import time

def read_byte_from_addr(ser, addr) -> str:
    # send "./busybox devmem 0x40000000 32" to the serial port
    ser.write(("/opt/nwsoc/busybox-armv5l devmem "+hex(addr)+" 32\n").encode())

    # wait 1s
    time.sleep(0.1)

    # read the response
    s = ''
    while ser.in_waiting:
        s += ser.read().decode("utf-8")

    #print(s)
    s = s.split("\n")[1][2:]
    # trim the newline
    s = s.strip()
    #print(s)
    return s

def decode_periphID(hex_id):
    #invert endianess
    hex_id = hex_id[14:16] + hex_id[12:14] + hex_id[10:12] + hex_id[8:10] + hex_id[6:8] + hex_id[4:6] + hex_id[2:4] + hex_id[0:2]

    # Convert hex to binary
    bin_id = bin(int(hex_id, 16))[2:].zfill(64)

    # print bits 0-11
    print("Part Number: " + bin_id[0:12])

    # print bits 12-18
    print("JEP 106 in use: " + bin_id[19])
    print("JEP 106: " + bin_id[12:19] + " " + hex(int(bin_id[12:19], 2)))
    # print bits 32-45
    print("JEP 106 continuation: " + bin_id[32:36] + " " + hex(int(bin_id[32:36], 2)))

    # print bits 20-23
    print("Revision: " + bin_id[20:24])

    # print bits 36-39
    print("4KB count: " + bin_id[36:40])


# open ttyUSB0 at baudrate 115200
ser = serial.Serial('/dev/ttyUSB0', 115200)

for i in range(0xf0072000, 0xf0073004, 0x4):
    #ID_0 = read_byte_from_addr(ser, i+0xFE0)
    #ID_1 = read_byte_from_addr(ser, i+0xFE4)
    #ID_2 = read_byte_from_addr(ser, i+0xFE8)
    #ID_3 = read_byte_from_addr(ser, i+0xFEC)
    #ID_4 = read_byte_from_addr(ser, i+0xFD0)
    #ID_5 = read_byte_from_addr(ser, i+0xFD4)
    #ID_6 = read_byte_from_addr(ser, i+0xFD8)
    #ID_7 = read_byte_from_addr(ser, i+0xFDC)
    print(hex(i) + " " + read_byte_from_addr(ser, i))

    #print("addr: " + hex(i) + " ID: " + ID_0+ID_1+ID_2+ID_3+ID_4+ID_5+ID_6+ID_7)
    #decode_periphID(ID_0+ID_1+ID_2+ID_3+ID_4+ID_5+ID_6+ID_7)


