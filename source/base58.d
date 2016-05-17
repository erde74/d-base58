/*
 * Copyright 2011 Google Inc.
 * ported to D (c) 2016 Stefan Hertenberger
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// https://github.com/bitcoinj/bitcoinj/blob/840df06b79beac1b984e6e247e90fcdedc4ad6e0/core/src/main/java/org/bitcoinj/core/Base58.java
module base58;

import std.bigint;
import std.conv;

/**
 * Base58 is a way to encode Bitcoin addresses (or arbitrary data) as alphanumeric strings.
 * <p>
 * Note that this is not the same base58 as used by Flickr, which you may find referenced around the Internet.
 * <p>
 * You may want to consider working with {@link VersionedChecksummedBytes} instead, which
 * adds support for testing the prefix and suffix bytes commonly found in addresses.
 * <p>
 * Satoshi explains: why base-58 instead of standard base-64 encoding?
 * <ul>
 * <li>Don't want 0OIl characters that look the same in some fonts and
 *     could be used to create visually identical looking account numbers.</li>
 * <li>A string with non-alphanumeric characters is not as easily accepted as an account number.</li>
 * <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>Doubleclicking selects the whole number as one word if it's all alphanumeric.</li>
 * </ul>
 * <p>
 * However, note that the encoding/decoding runs in O(n&sup2;) time, so it is not useful for large data.
 * <p>
 * The basic idea of the encoding is to treat the data bytes as a large number represented using
 * base-256 digits, convert the number to be represented using base-58 digits, preserve the exact
 * number of leading zeros (which are otherwise lost during the mathematical operations on the
 * numbers), and finally represent the resulting base-58 digits as alphanumeric ASCII characters.
 */
public class Base58 {
  public static char[] ALPHABET = cast(char[])"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  private static int[] INDEXES = new int[128];
  static this(){
    for (int i = 0; i < INDEXES.length; i++) {
      INDEXES[i] = -1;
    }
    for (int i = 0; i < ALPHABET.length; i++) {
      INDEXES[ALPHABET[i]] = i;
    }
  }
  
  /**
     * Encodes the given bytes as a base58 string (no checksum is appended).
     *
     * @param input the bytes to encode
     * @return the base58-encoded string
     */
  public static string encode(byte[] inp) {
    if (inp.length == 0) {
      return "";
    }       
    // Count leading zeros.
    int zeros = 0;
    while (zeros < inp.length && inp[zeros] == 0) {
      ++zeros;
    }
    // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
    auto input = new byte[inp.length];
    input[0 .. inp.length] = inp[0 .. $]; // since we modify it in-place
    auto encoded = new char[input.length * 2]; // upper bound
    auto outputStart = encoded.length;
    for (int inputStart = zeros; inputStart < input.length; ) {
      encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
      if (input[inputStart] == 0) {
        ++inputStart; // optimization - skip leading zeros
      }
    }
    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < encoded.length && encoded[outputStart] == ALPHABET[0]) {
      ++outputStart;
    }
    while (--zeros >= 0) {
      encoded[--outputStart] = ALPHABET[0];
    }
    // Return encoded string (including encoded leading zeros).
    return encoded[outputStart .. encoded.length].to!string();
  }
  
  /**
     * Decodes the given base58 string into the original data bytes.
     *
     * @param input the base58-encoded string to decode
     * @return the decoded data bytes
     * @throws AddressFormatException if the given string is not a valid base58 string
     */
  public static byte[] decode(string input) {
    if (input.length == 0) {
      return new byte[0];
    }
    // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
    byte[] input58 = new byte[input.length];
    for (int i = 0; i < input.length; ++i) {
      char c = input[i];
      int digit = c < 128 ? INDEXES[c] : -1;
      if (digit < 0) {
        throw new Exception("Illegal character " ~ c ~ " at position " ~ to!string(i));
      }
      input58[i] = cast(byte) digit;
    }
    // Count leading zeros.
    int zeros = 0;
    while (zeros < input58.length && input58[zeros] == 0) {
      ++zeros;
    }
    // Convert base-58 digits to base-256 digits.
    byte[] decoded = new byte[input.length];
    int outputStart = cast(int)decoded.length;
    for (int inputStart = zeros; inputStart < input58.length; ) {
      decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
      if (input58[inputStart] == 0) {
        ++inputStart; // optimization - skip leading zeros
      }
    }
    // Ignore extra leading zeroes that were added during the calculation.
    while (outputStart < decoded.length && decoded[outputStart] == 0) {
      ++outputStart;
    }
    // Return decoded data (including original number of leading zeros).
    return decoded[outputStart - zeros .. decoded.length];
  }
  
  public static BigInt decodeToBigInteger(string input) {
    return BigInt(cast(string)decode(input));
  }
  /+
    /**
     * Decodes the given base58 string into the original data bytes, using the checksum in the
     * last 4 bytes of the decoded data to verify that the rest are correct. The checksum is
     * removed from the returned data.
     *
     * @param input the base58-encoded string to decode (which should include the checksum)
     * @throws AddressFormatException if the input is not base 58 or the checksum does not validate.
     */
    public static byte[] decodeChecked(string input) {
        byte[] decoded  = decode(input);
        if (decoded.length < 4)
            throw new Exception("Input too short");
        byte[] data = decoded[0 .. decoded.length - 4];
        byte[] checksum = decoded[decoded.length - 4 .. decoded.length];
        byte[] actualChecksum = Arrays.copyOfRange(Sha256Hash.hashTwice(data), 0, 4);
        if (checksum != actualChecksum)
            throw new Exception("Checksum does not validate");
        return data;
    }
+/
  /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number the number to divide
     * @param firstDigit the index within the array of the first non-zero digit
     *        (this is used for optimization by skipping the leading zeros)
     * @param base the base in which the number's digits are represented (up to 256)
     * @param divisor the number to divide by (up to 256)
     * @return the remainder of the division operation
     */
  private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
    // this is just long division which accounts for the base of the input digits
    int remainder = 0;
    for (int i = firstDigit; i < number.length; i++) {
      int digit = cast(int) number[i] & 0xFF;
      int temp = remainder * base + digit;
      number[i] = cast(byte)(temp / divisor);
      remainder = temp % divisor;
    }
    return cast(byte) remainder;
  }
  
}
