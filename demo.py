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

xor_key = 0x69
private_key = lib.crypto.asymmetric.generate_private_key()
public_key = private_key.public_key

class Teamserver:
    pass

teamserver = Teamserver
teamserver.logging = lib.logging.Logging(True)

def cook_transmit_frame(teamserver, data):
    """

    :param teamserver:
    :param data: encoded/encrypted data ready to transmit
    :return:
    """

    # Symmetric Encryption Routine
    rc6_key = secrets.token_urlsafe(16)
    teamserver.logging.log(f"rc6 key: {rc6_key}", level="debug", source = "sender")
    transmit_data = lib.crypto.rc6.encrypt(rc6_key, data.encode('utf-8'))

    encrypted_frames = []
    for chunk_index in range(len(transmit_data)):
        frame_chunk = {"frame_id": chunk_index, "data": transmit_data[chunk_index],
                       "chunk_len": len(transmit_data)}
        encrypted_frames.append(frame_chunk)
    teamserver.logging.log(f"Encrypted instruction frames: {encrypted_frames}", level="debug", source="sender")

    # Encoding routine
    hex_frames = binascii.hexlify(pickle.dumps(encrypted_frames))
    hex_frames = lib.crypto.hex_encoding.encode_hex(hex_frames)
    enveloped_frames = lib.crypto.xor.single_byte_xor(hex_frames,
                                                     xor_key)
    teamserver.logging.log(f"Encoded data: {enveloped_frames}", level="debug", source="sender")

    enveloped_frames = lib.crypto.hex_encoding.encode_hex(binascii.hexlify(rc6_key.encode("utf-8"))) + enveloped_frames
    teamserver.logging.log(f"Unenveloped data: {enveloped_frames}", level="debug", source="sender")

    # Asymmetric Encryption
    lp_pubkey = public_key
    frame_box = lib.crypto.asymmetric.prepare_box(private_key, lp_pubkey)
    transmit_frames = lib.crypto.asymmetric.encrypt(frame_box, enveloped_frames)

    teamserver.logging.log(f"Enveloped data: {transmit_frames}", level="debug", source="sender")
    return transmit_frames


def uncook_transmit_frame(teamserver, frame):
    """

    :param teamserver:
    :param frame:
    :return:
    """

    teamserver.logging.log(f"Enveloped data: {frame}", level="debug", source="recipient")
    # Asymmetric Encryption Routine
    lp_pubkey = public_key
    frame_box = lib.crypto.asymmetric.prepare_box(private_key, lp_pubkey)
    transmit_frame = lib.crypto.asymmetric.decrypt(frame_box, frame)

    teamserver.logging.log(f"Unenveloped data: {transmit_frame}", level="debug", source="recipient")
    # Decoding Routine
    rc6_key = binascii.unhexlify(lib.crypto.hex_encoding.decode_hex(transmit_frame[0:44])).decode("utf-8")
    teamserver.logging.log(f"extracted rc6 key: {rc6_key}", level="debug", source="lib.networking")
    unxord_frame = lib.crypto.xor.single_byte_xor(transmit_frame,
                                                 xor_key)
    unenc_frame = lib.crypto.hex_encoding.decode_hex(unxord_frame)
    del unxord_frame
    unsorted_recv_frame = pickle.loads(binascii.unhexlify(unenc_frame[44:]))
    del unenc_frame

    teamserver.logging.log(f"Decoded data: {unsorted_recv_frame}", level="debug", source="recipient")
    data_list = []
    sorted_frames = sorted(unsorted_recv_frame, key=lambda i: i['frame_id'])
    del unsorted_recv_frame
    for data_index in range(len(sorted_frames)):
        data_list.append(sorted_frames[data_index]['data'])

    # Symmetric decryption routine
    decrypted_data = lib.crypto.rc6.decrypt(rc6_key, data_list)
    instruction_frame = ast.literal_eval(decrypted_data.decode('utf-8'))
    teamserver.logging.log(f"Decrypted instruction frame: {instruction_frame}", level="debug", source="recipient")

    return decrypted_data


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
