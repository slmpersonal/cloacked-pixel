import sys
import struct
import numpy
import matplotlib.pyplot as plt

from PIL import Image

from crypt import AESCipher


# Decompose a binary file into an array of bits
def decompose(data):
    v = []

    # Pack file len in 4 bytes
    f_size = len(data)
    byte_size = [ord(b) for b in struct.pack("i", f_size)]

    byte_size += [ord(b) for b in data]

    for b in byte_size:
        for i in range(7, -1, -1):
            v.append((b >> i) & 0x1)

    return v


# Assemble an array of bits into a binary file
def assemble(v):
    byte_size = ""

    length = len(v)
    for idx in range(0, int(len(v) / 8)):
        byte = 0
        for i in range(0, 8):
            if idx * 8 + i < length:
                byte = (byte << 1) + v[idx * 8 + i]
        byte_size = byte_size + chr(byte)

    payload_size = struct.unpack("i", byte_size[:4])[0]

    return byte_size[4: payload_size + 4]


# Set the i-th bit of v to x
def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n


# Embed payload file into LSB bits of an image
def embed(img_file, payload, password):
    # Process source image
    img = Image.open(img_file)
    (width, height) = img.size
    conv = img.convert("RGBA").getdata()
    print("[*] Input image size: %dx%d pixels." % (width, height))
    max_size = width * height * 3.0 / 8 / 1024  # max payload size
    print("[*] Usable payload size: %.2f KB." % max_size)

    f = open(payload, "rb")
    data = f.read()
    f.close()
    print("[+] Payload size: %.3f KB " % (len(data) / 1024.0))

    # Encypt
    cipher = AESCipher(password)
    data_enc = cipher.encrypt(data)

    # Process data from payload file
    v = decompose(data_enc)

    # Add until multiple of 3
    while len(v) % 3:
        v.append(0)

    payload_size = len(v) / 8 / 1024.0
    print("[+] Encrypted payload size: %.3f KB " % payload_size)
    if payload_size > max_size - 4:
        print("[-] Cannot embed. File too large")
        sys.exit()

    # Create output image
    steg_img = Image.new('RGBA', (width, height))
    data_img = steg_img.getdata()

    idx = 0

    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            if idx < len(v):
                r = set_bit(r, 0, v[idx])
                g = set_bit(g, 0, v[idx + 1])
                b = set_bit(b, 0, v[idx + 2])
            data_img.putpixel((w, h), (r, g, b, a))
            idx = idx + 3

    steg_img.save(img_file + "-stego.png", "PNG")

    print("[+] %s embedded successfully!" % payload)


# Extract data embedded into LSB of the input file
def extract(in_file, out_file, password):
    # Process source image
    img = Image.open(in_file)
    (width, height) = img.size
    conv = img.convert("RGBA").getdata()
    print("[+] Image size: %dx%d pixels." % (width, height))

    # Extract LSBs
    v = []
    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            v.append(r & 1)
            v.append(g & 1)
            v.append(b & 1)

    data_out = assemble(v)

    # Decrypt
    cipher = AESCipher(password)
    data_dec = cipher.decrypt(data_out)

    # Write decrypted data
    out_f = open(out_file, "wb")
    out_f.write(data_dec)
    out_f.close()

    print("[+] Written extracted data to %s." % out_file)


# Statistical analysis of an image to detect LSB steganography
def analyse(in_file):
    # Split the image into blocks.
    # Compute the average value of the LSBs for each block.
    # The plot of the averages should be around 0.5 for zones that contain
    # hidden encrypted messages (random data).
    block_size = 100
    img = Image.open(in_file)
    (width, height) = img.size
    print("[+] Image size: %dx%d pixels." % (width, height))
    conv = img.convert("RGBA").getdata()

    # Extract LSBs
    vr = []  # Red LSBs
    vg = []  # Green LSBs
    vb = []  # LSBs
    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            vr.append(r & 1)
            vg.append(g & 1)
            vb.append(b & 1)

    # Average colours' LSB per each block
    avg_r = []
    avg_g = []
    avg_b = []
    for i in range(0, len(vr), block_size):
        avg_r.append(numpy.mean(vr[i:i + block_size]))
        avg_g.append(numpy.mean(vg[i:i + block_size]))
        avg_b.append(numpy.mean(vb[i:i + block_size]))

    # Nice plot
    num_blocks = len(avg_r)
    blocks = [i for i in range(0, num_blocks)]
    plt.axis([0, len(avg_r), 0, 1])
    plt.ylabel('Average LSB per block')
    plt.xlabel('Block number')

    # plt.plot(blocks, avg_r, 'r.')
    # plt.plot(blocks, avg_g, 'g')
    plt.plot(blocks, avg_b, 'bo')

    plt.show()


def usage(prog_name):
    print("LSB steganography. Hide files within least significant bits of images.\n")
    print("Usage:")
    print("  %s hide <img_file> <payload_file> <password>" % prog_name)
    print("  %s extract <stego_file> <out_file> <password>" % prog_name)
    print("  %s analyse <stego_file>" % prog_name)
    sys.exit()


if __name__ != "__main__":
    pass
else:
    if len(sys.argv) < 3:
        usage(sys.argv[0])

    if sys.argv[1] == "hide":
        embed(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "analyse":
        analyse(sys.argv[2])
    else:
        print("[-] Invalid operation specified")

#%%

#%%
