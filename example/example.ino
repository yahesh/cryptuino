/*
 * File:    example.ino
 * Author:  Yahe <hello@yahe.sh>
 * Version: 0.1.0
 *
 * Created on 14. April 2013
 * Release 0.1.0 on 26. April 2013
 */

#include <arc4uino.h>
#include <base64uino.h>
#include <sha1uino.h>

#define MEMORY_SIZE   0x0400
#define MEMORY_CHUNKS 0x20

#define MODE_ARC4_ENC   0x00
#define MODE_ARC4_DEC   0x01
#define MODE_BASE64_ENC 0x02
#define MODE_BASE64_DEC 0x03
#define MODE_SHA1_HASH  0x04
#define MODE_SHA1_HMAC  0x05
#define MODE_ECHO       0x06

#define SERIAL_RATE        0x2580
#define SERIAL_LINE_LENGTH 0x40

#define ASCII_LF 0x0A
#define ASCII_CR 0x0D

// saves the mode we are in
uint8_t MODE = 0x00;

bool __chunkCompare(CHUNK input, char* text, CHUNK_SIZE textlen) {
  
  bool result = false;
  
  if ((CHUNK_ERROR != input) && (NULL != text)) {
    if (textlen == sizeof_chunk(input)) {
      CHUNK_SIZE index = 0x00;
      for (index = 0x00; index < textlen; index++) {
        result = (text[index] == get_chunk(input, index));
        if (!result) {
          break;
        }
      }
    }
  }
  
  return result;
}

bool __checkMode(CHUNK input) {
  
  bool result = false;
  
  if (CHUNK_ERROR != input) {
    if (__chunkCompare(input, "!arc4:enc", 0x09)) {
      result = __setMode(MODE_ARC4_ENC);
    }
    if (__chunkCompare(input, "!arc4:dec", 0x09)) {
      result = __setMode(MODE_ARC4_DEC);
    }
    if (__chunkCompare(input, "!base64:enc", 0x0B)) {
      result = __setMode(MODE_BASE64_ENC);
    }
    if (__chunkCompare(input, "!base64:dec", 0x0B)) {
      result = __setMode(MODE_BASE64_DEC);
    }
    if (__chunkCompare(input, "!sha1:hash", 0x0A)) {
      result = __setMode(MODE_SHA1_HASH);
    }
    if (__chunkCompare(input, "!sha1:hmac", 0x0A)) {
      result = __setMode(MODE_SHA1_HMAC);
    }
    if (__chunkCompare(input, "!echo", 0x05)) {
      result = __setMode(MODE_ECHO);
    }
    if (__chunkCompare(input, "!help", 0x05)) {
      Serial.println("!arc4:enc");
      Serial.println("!arc4:dec");
      Serial.println("!base64:enc");
      Serial.println("!base64:dec");
      Serial.println("!sha1:hash");
      Serial.println("!sha1:hmac");
      Serial.println("!echo");
      Serial.println("!help");
      result = true;
    }
  }
  
  return result;
  
}

void __printHexLine(CHUNK input) {

  if(CHUNK_ERROR != input) {
    CHUNK_SIZE index = 0x00;
    for (index = 0x00; index < sizeof_chunk(input); index++) {
      if (get_chunk(input, index) < 0x10) {
        Serial.print("0");
      }
      Serial.print(get_chunk(input, index), HEX);
    }
    Serial.println("");
  }

}

void __printLine(CHUNK input) {

  if(CHUNK_ERROR != input) {
    CHUNK_SIZE index = 0x00;
    for (index = 0x00; index < sizeof_chunk(input); index++) {
      Serial.print((char)get_chunk(input, index));
    }
    Serial.println("");
  }

}

CHUNK __readPassword() {
  
  Serial.print("PASSWORD: ");
  
  CHUNK result = __readLine();
  
  if (CHUNK_ERROR == result) {
    Serial.println("");
    Serial.println("NO PASSWORD PROVIDED");
  } else {
    Serial.println("*********");
  }
  
  return result;
  
}

CHUNK __readLine() {

  CHUNK result = alloc_chunk(SERIAL_LINE_LENGTH);
  
  if (CHUNK_ERROR != result) {
    CHUNK_SIZE count = 0x00;
    CHUNK_TYPE next = 0x00;
    
    do {
      if (Serial.available()) {
        next = (CHUNK_TYPE)Serial.read();
      
        if ((ASCII_LF != next) && (ASCII_CR != next)) {
          set_chunk(result, count, next);
          count++;
        }
      }
    } while ((ASCII_LF != next) && (ASCII_CR != next) && (SERIAL_LINE_LENGTH > count));
    
    if (0x00 == count) {
      dealloc_chunk(result);
      result = CHUNK_ERROR;
    } else {
      if (SERIAL_LINE_LENGTH > count) {
        resize_chunk(result, count);
      }
    }
  }

  return result;

}

bool __setMode(uint8_t mode) {

  bool result = true;
  
  MODE = mode;
  Serial.print("MODE: ");
  switch (mode) {
    case MODE_ARC4_ENC:
      Serial.println("ARC4-encrypt");
      break;

    case MODE_ARC4_DEC:
      Serial.println("ARC4-decrypt");
      break;

    case MODE_BASE64_ENC:
      Serial.println("BASE64-encode");
      break;

    case MODE_BASE64_DEC:
      Serial.println("BASE64-decode");
      break;

    case MODE_SHA1_HASH:
      Serial.println("SHA1-hash");
      break;

    case MODE_SHA1_HMAC:
      Serial.println("SHA1-hmac");
      break;

    case MODE_ECHO:
      Serial.println("ECHO");
      break;

    default:
      result = false;
      Serial.println("UNKNOWN MODE");
  }
  
  return result;
  
}

void setup() {
  
  // initialize memory
  init_chunk(MEMORY_SIZE, MEMORY_CHUNKS);
  
  // enable serial communication
  Serial.begin(SERIAL_RATE);
  // for Arduino Leonardo
  while (!Serial) {};
  
  Serial.println("EXAMPLE.INO: 0.1.0");
  Serial.println("KENNETH NEWWOOD");
  Serial.println("<KENNETH@NEWWOOD.DE>");
  Serial.println("");

  // set mode of operation
  __setMode(MODE_ARC4_ENC);
  Serial.println("");

}

void loop() {

  Serial.print("> ");

  CHUNK base64 = CHUNK_ERROR;
  CHUNK input = __readLine();
  CHUNK output = CHUNK_ERROR;
  CHUNK password = CHUNK_ERROR;
  __printLine(input);

  if (CHUNK_ERROR != input) {
    if (!__checkMode(input)) {
      switch (MODE) {
        case MODE_ARC4_ENC:
          password = __readPassword();
          output = encrypt_arc4(input, password);
          base64 = encode_base64(output);
          if (CHUNK_ERROR != base64) {
            __printLine(base64);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_ARC4_DEC:
          password = __readPassword();
          base64 = decode_base64(input);
          output = decrypt_arc4(base64, password);
          if (CHUNK_ERROR != output) {
            __printLine(output);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_BASE64_ENC:
          output = encode_base64(input);
          if (CHUNK_ERROR != output) {
            __printLine(output);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_BASE64_DEC:
          output = decode_base64(input);
          if (CHUNK_ERROR != output) {
            __printLine(output);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_SHA1_HASH:
          output = hash_sha1(input);
          if (CHUNK_ERROR != output) {
            __printHexLine(output);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_SHA1_HMAC:
          password = __readPassword();
          output = hmac_sha1(input, password);
          if (CHUNK_ERROR != output) {
            __printHexLine(output);
          } else {
            Serial.println("SOME ERROR HAPPENED");
          }
          break;

        case MODE_ECHO:
          __printLine(input);
          break;
      }
    }

    // free up memory
    if (CHUNK_ERROR != base64) {
      dealloc_chunk(base64);
    }
    if (CHUNK_ERROR != output) {
      dealloc_chunk(output);
    }
    dealloc_chunk(input); 
   
    // clean up memory
    zeroFreeMem_chunk(); 
  }
  
  Serial.println("");

}

