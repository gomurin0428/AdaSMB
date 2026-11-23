with Interfaces;

--  The MD5 Message-Digest Algorithm (RFC 1321, April 1992), which NTLM uses
--  for HMAC-MD5 (NTLMv2) and the session's signing keys. Section numbers
--  are the RFC's. Every message here is a whole number of bytes, and a
--  word's bytes are little-endian (section 2: "each consecutive group of
--  four bytes is interpreted as a word with the low-order (least
--  significant) byte given first").
package SMB.Spec.MD5
  with Ghost, SPARK_Mode
is
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   --  2: a word is a 32-bit quantity.
   subtype Word is Interfaces.Unsigned_32;

   type Words is array (Natural range <>) of Word;

   --  The messages this specification takes: any bound above the core's
   --  keeps the arithmetic here in Natural.
   Maximum_Length : constant := 2 ** 30;

   --  2: "X <<< s", X "circularly shifted (rotated) left by s bit
   --  positions".
   function Rotate_Left (X : Word; S : Natural) return Word is
     (Interfaces.Shift_Left (X, S) or Interfaces.Shift_Right (X, 32 - S))
   with Pre => S < 32;

   --  3.1: "a single "1" bit is appended to the message, and then "0" bits
   --  are appended so that the length in bits of the padded message becomes
   --  congruent to 448, modulo 512". With whole bytes, the bit 1 and seven
   --  zero bits are the byte 16#80#, followed by this many zero bytes:
   function Zero_Bytes (Length : Natural) return Natural is
     ((55 - Length) mod 64)
   with Pre => Length <= Maximum_Length;

   --  3.2: then "a 64-bit representation of b" (the message's length in
   --  bits) "appended ... as two 32-bit words and appended low-order word
   --  first": its eight bytes, the least significant first.
   function Padded_Length (Length : Natural) return Natural is
     (Length + 1 + Zero_Bytes (Length) + 8)
   with Pre => Length <= Maximum_Length;

   function Length_Byte (Length : Natural; Index : Natural) return SMB.Byte
   is
     (SMB.Byte
        ((Interfaces.Unsigned_64 (Length) * 8 / 2 ** (8 * Index)) mod 256))
   with Pre => Length <= Maximum_Length and then Index < 8;

   function Padded_Byte (Message : SMB.Bytes; Index : Natural) return SMB.Byte
   is
     (if Index < Message'Length then Message (Message'First + Index)
      elsif Index = Message'Length then 16#80#
      elsif Index < Message'Length + 1 + Zero_Bytes (Message'Length) then 0
      else
        Length_Byte
          (Message'Length,
           Index - (Message'Length + 1 + Zero_Bytes (Message'Length))))
   with Pre =>
     Message'Length <= Maximum_Length
     and then Index < Padded_Length (Message'Length);

   subtype Block is SMB.Bytes (0 .. 63);

   --  3.4: "each 16-word block", the (N + 1)th of the padded message.
   function Padded_Block (Message : SMB.Bytes; N : Natural) return Block is
     (for Index in Block'Range => Padded_Byte (Message, 64 * N + Index))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N < Padded_Length (Message'Length) / 64;

   --  X[J], word J of a block, the low-order byte first.
   function Block_Word (B : Block; J : Natural) return Word is
     (Word (B (4 * J)) + Word (B (4 * J + 1)) * 2 ** 8
      + Word (B (4 * J + 2)) * 2 ** 16 + Word (B (4 * J + 3)) * 2 ** 24)
   with Pre => J < 16;

   --  3.3: the four-word buffer (A, B, C, D), "initialized to the
   --  following values in hexadecimal, low-order bytes first: word A: 01 23
   --  45 67, word B: 89 ab cd ef, word C: fe dc ba 98, word D: 76 54 32
   --  10".
   type Buffer is record
      A, B, C, D : Word;
   end record;

   Initial : constant Buffer :=
     (A => 16#6745_2301#, B => 16#EFCD_AB89#,
      C => 16#98BA_DCFE#, D => 16#1032_5476#);

   --  3.4: the four auxiliary functions.
   function F (X, Y, Z : Word) return Word is ((X and Y) or ((not X) and Z));
   function G (X, Y, Z : Word) return Word is ((X and Z) or (Y and (not Z)));
   function H (X, Y, Z : Word) return Word is (X xor Y xor Z);
   function I (X, Y, Z : Word) return Word is (Y xor (X or (not Z)));

   --  3.4: T[i] (here T (i - 1)), "the integer part of 4294967296 times
   --  abs(sin(i)), where i is in radians".
   T : constant Words (0 .. 63) :=
     (16#D76AA478#, 16#E8C7B756#, 16#242070DB#, 16#C1BDCEEE#,
      16#F57C0FAF#, 16#4787C62A#, 16#A8304613#, 16#FD469501#,
      16#698098D8#, 16#8B44F7AF#, 16#FFFF5BB1#, 16#895CD7BE#,
      16#6B901122#, 16#FD987193#, 16#A679438E#, 16#49B40821#,
      16#F61E2562#, 16#C040B340#, 16#265E5A51#, 16#E9B6C7AA#,
      16#D62F105D#, 16#02441453#, 16#D8A1E681#, 16#E7D3FBC8#,
      16#21E1CDE6#, 16#C33707D6#, 16#F4D50D87#, 16#455A14ED#,
      16#A9E3E905#, 16#FCEFA3F8#, 16#676F02D9#, 16#8D2A4C8A#,
      16#FFFA3942#, 16#8771F681#, 16#6D9D6122#, 16#FDE5380C#,
      16#A4BEEA44#, 16#4BDECFA9#, 16#F6BB4B60#, 16#BEBFBC70#,
      16#289B7EC6#, 16#EAA127FA#, 16#D4EF3085#, 16#04881D05#,
      16#D9D4D039#, 16#E6DB99E5#, 16#1FA27CF8#, 16#C4AC5665#,
      16#F4292244#, 16#432AFF97#, 16#AB9423A7#, 16#FC93A039#,
      16#655B59C3#, 16#8F0CCC92#, 16#FFEFF47D#, 16#85845DD1#,
      16#6FA87E4F#, 16#FE2CE6E0#, 16#A3014314#, 16#4E0811A1#,
      16#F7537E82#, 16#BD3AF235#, 16#2AD7D2BB#, 16#EB86D391#);

   --  3.4's 64 operations [abcd k s i], in order: the word k and the shift
   --  s of each (rounds 1 to 4, sixteen each).
   K_Index : constant array (0 .. 63) of Natural :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
      5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
      0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9);

   Shift : constant array (0 .. 63) of Natural :=
     (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21);

   --  The operation's function: F in round 1, G in 2, H in 3, I in 4.
   function Round_Function (Step : Natural; X, Y, Z : Word) return Word is
     (case Step / 16 is
         when 0 => F (X, Y, Z),
         when 1 => G (X, Y, Z),
         when 2 => H (X, Y, Z),
         when others => I (X, Y, Z))
   with Pre => Step < 64;

   --  3.4: operation Step (0 .. 63) on the buffer: [abcd k s i] is
   --  a = b + ((a + Fn (b, c, d) + X[k] + T[i]) <<< s). The RFC writes the
   --  next operation with the names turned (ABCD, DABC, CDAB, BCDA); here
   --  the buffer turns instead, so that each operation updates its A: the
   --  word just updated becomes B, and the old D becomes A.
   function Operation (V : Buffer; Step : Natural; X : Word) return Buffer is
     (A => V.D,
      B => V.B + Rotate_Left
             (V.A + Round_Function (Step, V.B, V.C, V.D) + X + T (Step),
              Shift (Step)),
      C => V.B,
      D => V.C)
   with Pre => Step < 64;

   --  The buffer after the first N operations on a block, from V.
   function Operations (V : Buffer; B : Block; N : Natural) return Buffer is
     (if N = 0 then V
      else Operation
             (Operations (V, B, N - 1), N - 1,
              Block_Word (B, K_Index (N - 1))))
   with Pre => N <= 64,
     Subprogram_Variant => (Decreases => N);

   --  3.4, a block: after the 64 operations (a multiple of four, so the
   --  names are back in place), "A = A + AA, B = B + BB, C = C + CC,
   --  D = D + DD".
   function Compress (V : Buffer; B : Block) return Buffer is
     (declare
         R : constant Buffer := Operations (V, B, 64);
      begin
         (A => R.A + V.A, B => R.B + V.B, C => R.C + V.C, D => R.D + V.D));

   --  The buffer after the first N blocks of the padded message.
   function Hash_Blocks (Message : SMB.Bytes; N : Natural) return Buffer is
     (if N = 0 then Initial
      else Compress
             (Hash_Blocks (Message, N - 1), Padded_Block (Message, N - 1)))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N <= Padded_Length (Message'Length) / 64,
     Subprogram_Variant => (Decreases => N);

   --  Byte Index (0 for the least significant) of a word.
   function Word_Byte (X : Word; Index : Natural) return SMB.Byte is
     (SMB.Byte ((X / 2 ** (8 * Index)) mod 256))
   with Pre => Index < 4;

   subtype Digest is SMB.Bytes (0 .. 15);

   --  3.5: "The message digest produced as output is A, B, C, D. That is,
   --  we begin with the low-order byte of A, and end with the high-order
   --  byte of D."
   function Digest_Of (V : Buffer) return Digest is
     (for Index in Digest'Range =>
        Word_Byte
          ((case Index / 4 is
               when 0 => V.A,
               when 1 => V.B,
               when 2 => V.C,
               when others => V.D),
           Index mod 4));

   function MD5 (Message : SMB.Bytes) return Digest is
     (Digest_Of (Hash_Blocks (Message, Padded_Length (Message'Length) / 64)))
   with Pre => Message'Length <= Maximum_Length;

   --  A message hashed as it arrives, a byte at a time, as SMB.Spec.SHA2's
   --  model for SHA-256 (SMB.Spec.MD5.Lemmas ties it to MD5).

   subtype Block_Position is Natural range 0 .. 63;

   type State is record
      Value : Buffer;
      Pending : Block;
      Used : Block_Position;
   end record;

   Start : constant State :=
     (Value => Initial, Pending => (others => 0), Used => 0);

   function Put (B : Block; Position : Block_Position; Byte : SMB.Byte)
     return Block
   is
     ((B with delta Position => Byte));

   function Absorb_Byte (S : State; Byte : SMB.Byte) return State is
     (if S.Used = 63
      then (Value => Compress (S.Value, Put (S.Pending, S.Used, Byte)),
            Pending => Put (S.Pending, S.Used, Byte),
            Used => 0)
      else (Value => S.Value,
            Pending => Put (S.Pending, S.Used, Byte),
            Used => S.Used + 1));

   function Absorb_Prefix
     (S : State; Message : SMB.Bytes; N : Natural) return State
   is
     (if N = 0 then S
      else Absorb_Byte
             (Absorb_Prefix (S, Message, N - 1),
              Message (Message'First + (N - 1))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Subprogram_Variant => (Decreases => N);

   function Absorb (S : State; Message : SMB.Bytes) return State is
     (Absorb_Prefix (S, Message, Message'Length))
   with Pre => Message'Length <= Maximum_Length;

   function Pad_Block (S : State) return Block is
     (for J in Block'Range =>
        (if J < S.Used then S.Pending (J)
         elsif J = S.Used then 16#80#
         else 0));

   function Length_Block (S : State; Length : Natural) return Block is
     (for J in Block'Range =>
        (if J >= 56 then Length_Byte (Length, J - 56)
         elsif S.Used < 56 then Pad_Block (S) (J)
         else 0))
   with Pre => Length <= Maximum_Length;

   function Before_Length (S : State) return Buffer is
     (if S.Used < 56 then S.Value else Compress (S.Value, Pad_Block (S)));

   function Finish (S : State; Length : Natural) return Digest is
     (Digest_Of (Compress (Before_Length (S), Length_Block (S, Length))))
   with Pre => Length <= Maximum_Length;
end SMB.Spec.MD5;
