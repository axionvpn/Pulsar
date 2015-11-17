#pragma once

typedef BOOL (*ENCODER_FUNC)(BYTE *, int, BYTE **, int *);
typedef BOOL (*DECODER_FUNC)(BYTE *, int, BYTE **, int *);

BOOL base64Encoder(BYTE *plaintext, int plaintextLen, BYTE **encodedText, int *encodedLen);
BOOL base64Decoder(BYTE *encodedText, int encodedLen, BYTE **decodedText, int *decodedLen);