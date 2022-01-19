import pickle
import binascii
import ast
import secrets
import time
import uuid

import lib.crypto.rc6
import lib.crypto.hex_encoding
import lib.crypto.xor
import lib.crypto.asymmetric
import lib.logging

# Select a 'random' xor key (https://xkcd.com/221/)
xor_key = 0x69
# Generate a private key
private_key = lib.crypto.asymmetric.generate_private_key()
# Get the public key of generated private key
public_key = private_key.public_key

class Teamserver:
    pass

teamserver = Teamserver
teamserver.logging = lib.logging.Logging(True)

def cook_transmit_frame(teamserver, data):
    """
    Encrypt an instruction frame and convert it to a transmit frame.

    :param teamserver:
    :param data: encoded/encrypted data ready to transmit
    :return:
    """

    # Symmetric Encryption Routine
    #  instruction frame -> encrypted data frame
    # Generate a random RC6 key
    rc6_key = secrets.token_urlsafe(16)
    teamserver.logging.log(f"rc6 key: {rc6_key}", level="debug", source = "sender")
    # Encrypt instruction_frame with RC6
    encrypted_instruction_data = lib.crypto.rc6.encrypt(rc6_key, data.encode('utf-8'))

    # Chunk the resulting encrypted instructions and label them
    data_frames = []
    for chunk_index in range(len(encrypted_instruction_data)):
        frame_chunk = {
                "frame_id": chunk_index, 
                "data": encrypted_instruction_data[chunk_index],
                "chunk_len": len(encrypted_instruction_data)
        }
        data_frames.append(frame_chunk)
    teamserver.logging.log(f"Encrypted data_frames frames: {data_frames}", level="debug", source="sender")

    # Encoding routine
    #  encrypted data frame -> encoded and encrypted data frame
    # Convert the encoded list to a hexadecimal representation
    hex_frames = binascii.hexlify(pickle.dumps(data_frames))
    # Use our "hex encoding" library to 'corrupt' the hex data
    hex_frames = lib.crypto.hex_encoding.encode_hex(hex_frames)
    # Xor the hex data
    enveloped_frames = lib.crypto.xor.single_byte_xor(hex_frames,
                                                     xor_key)
    teamserver.logging.log(f"Encoded data: {enveloped_frames}", level="debug", source="sender")
    
    # Convert the RC6 key to hex, 'hex encode' it, then prepend it to our frames
    enveloped_frames = lib.crypto.hex_encoding.encode_hex(binascii.hexlify(rc6_key.encode("utf-8"))) + enveloped_frames
    teamserver.logging.log(f"Unenveloped data: {enveloped_frames}", level="debug", source="sender")

    # Asymmetric Encryption
    #  encoded and encrypted data frame -> encrypted transmit frame
    lp_pubkey = public_key  # We're only using one key pair here, but you can tweak this to rotate keys, use new key pairs, etc
    # Make a box to hold our data in
    frame_box = lib.crypto.asymmetric.prepare_box(private_key, lp_pubkey)
    # Encrypt the data using our private key and the public key of the recipient
    transmit_frames = lib.crypto.asymmetric.encrypt(frame_box, enveloped_frames)

    teamserver.logging.log(f"Enveloped data: {transmit_frames}", level="debug", source="sender")
    return transmit_frames


def uncook_transmit_frame(teamserver, frame):
    """
    Decrypt a transmit frame and extract the resulting instruction frame

    :param teamserver:
    :param frame: the encrypted transmit frame to be decrypted
    :return:
    """

    teamserver.logging.log(f"Enveloped data: {frame}", level="debug", source="recipient")
    # Asymmetric Encryption Routine
    #   encrypted transmit frame -> encoded and encrypted data frame
    # We are now the "recipient" of the data
    # Grab the public key of the sender
    lp_pubkey = public_key  # Intentionally confusing since this is a demo
    # Decrypt the data with our private key and the public key of the sender. They encrypted it with their private key and our public key
    frame_box = lib.crypto.asymmetric.prepare_box(private_key, lp_pubkey)
    data_frame = lib.crypto.asymmetric.decrypt(frame_box, frame)
    teamserver.logging.log(f"Unenveloped data: {data_frame}", level="debug", source="recipient")

    # Decoding Routine
    #  encoded and encrypted data frame -> encrypted data frame
    # Extract the rc6 key from the message. It's always the first 44 bytes. Decode appropriately
    rc6_key = binascii.unhexlify(lib.crypto.hex_encoding.decode_hex(data_frame[0:44])).decode("utf-8")
    teamserver.logging.log(f"extracted rc6 key: {rc6_key}", level="debug", source="lib.networking")
    # Unxor the frame
    unxord_frame = lib.crypto.xor.single_byte_xor(data_frame,
                                                 xor_key)
    # Decode the frame
    unenc_frame = lib.crypto.hex_encoding.decode_hex(unxord_frame)  # Could be combined with previous instruction for brevity
    del unxord_frame  # Garbage collection, we don't want this in memory
    # This will give us an unsorted list. Each entry has an index key 'frame_id'
    unsorted_recv_frame = pickle.loads(binascii.unhexlify(unenc_frame[44:]))
    del unenc_frame  # Garbage collection, we don't want this in memory

    teamserver.logging.log(f"Decoded data: {unsorted_recv_frame}", level="debug", source="recipient")
    # Sort our data frames on the index key
    data_list = []
    sorted_frames = sorted(unsorted_recv_frame, key=lambda i: i['frame_id'])
    del unsorted_recv_frame  # Garbage collection, we don't want this in memory
    # This is probably unnecessary
    for data_index in range(len(sorted_frames)):
        data_list.append(sorted_frames[data_index]['data'])

    # Symmetric decryption routine
    #  encrypted data frame -> instruction_frame
    # Using the extracted rc6 key, decrypt the list of data
    decrypted_data = lib.crypto.rc6.decrypt(rc6_key, data_list)
    # Reconstruct the instruction frame
    instruction_frame = ast.literal_eval(decrypted_data.decode('utf-8'))
    teamserver.logging.log(f"Decrypted instruction frame: {instruction_frame}", level="debug", source="recipient")

    return decrypted_data

# This is our raw 'instruction_frame' we will be sending
message = {'command': 'shell_exec',
           'args': 'cmd.exe /c calc.exe',
           'transaction_id': uuid.uuid4().hex,
           'date': time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime())
           }
teamserver.logging.log(f"Initial instruction frame: {message}", level="debug", source="init")

# transmit_frame would represent the frame sourced from the sender, and relayed via a transport
transmit_frame = cook_transmit_frame(teamserver, str(message))

# this represents the actions that happen on the recipient side, received from a transport
uncook_transmit_frame(teamserver, transmit_frame)
