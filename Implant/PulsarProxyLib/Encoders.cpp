#include "stdafx.h"

BOOL base64Encoder(BYTE *plaintext, int plaintextLen, BYTE **encodedText, int *encodedLen) {
	*encodedLen = Base64EncodeGetRequiredLength(plaintextLen, ATL_BASE64_FLAG_NONE);
	DBGPrint("encodedRequestLen: %d\n", *encodedLen);
	*encodedText = new BYTE[*encodedLen+1];

	if (!Base64Encode(plaintext, plaintextLen, (LPSTR)*encodedText, encodedLen, ATL_BASE64_FLAG_NONE)) {
		DBGPrint("ERROR (Base64Encode) 0x%x\n", GetLastError());
		delete [] encodedText;
		return FALSE;
	}

	(*encodedText)[*encodedLen] = 0;

	return TRUE;
}


BOOL base64Decoder(BYTE *encodedText, int encodedLen, BYTE **decodedText, int *decodedLen) {
	*decodedLen = Base64DecodeGetRequiredLength(encodedLen);
	*decodedText = new BYTE[*decodedLen+1];

	if(!Base64Decode((LPCSTR)encodedText, encodedLen, *decodedText, decodedLen)){
		DBGPrint("ERROR (Base64Encode) 0x%x\n", GetLastError());
		delete [] decodedText;
		return FALSE;
	}

	return TRUE;
}