with Interfaces;

--  The Secure Hash Standard (FIPS PUB 180-4, August 2015): SHA-256, which
--  SMB 2.x signing (HMAC-SHA256) and the SMB 3.1.1 key derivation use, and
--  SHA-512, which the SMB 3.1.1 preauth integrity hash uses.
--  Section numbers are the standard's. Every message here is a whole number
--  of bytes, and a word's bytes are big-endian (section 3.1: "the most
--  significant bit is stored in the left-most bit position"), so the
--  message's first byte is the most significant byte of the first block's
--  first word.
package SMB.Spec.SHA2
  with Ghost, SPARK_Mode
is
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   --  2.1: a word of w = 32 bits.
   subtype Word_32 is Interfaces.Unsigned_32;

   --  The messages this specification takes. The standard allows up to
   --  2**64 - 1 bits; the core hashes at most a frame and a block, and any
   --  bound above that keeps the arithmetic here in Natural.
   Maximum_Length : constant := 2 ** 30;

   --  2.2.2 and 3.2: SHR^n (x) = x >> n, and ROTR^n (x) =
   --  (x >> n) or (x << w - n), for 0 <= n < w; x << n discards the n
   --  left-most bits of x and pads the result with n zeros on the right.
   function SHR (X : Word_32; N : Natural) return Word_32 is
     (Interfaces.Shift_Right (X, N))
   with Pre => N < 32;

   function ROTR (X : Word_32; N : Natural) return Word_32 is
     (Interfaces.Shift_Right (X, N) or Interfaces.Shift_Left (X, 32 - N))
   with Pre => N < 32;

   --  4.1.2: the SHA-256 functions.
   function Ch (X, Y, Z : Word_32) return Word_32 is
     ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word_32) return Word_32 is
     ((X and Y) xor (X and Z) xor (Y and Z));

   function Big_Sigma_0 (X : Word_32) return Word_32 is
     (ROTR (X, 2) xor ROTR (X, 13) xor ROTR (X, 22));

   function Big_Sigma_1 (X : Word_32) return Word_32 is
     (ROTR (X, 6) xor ROTR (X, 11) xor ROTR (X, 25));

   function Small_Sigma_0 (X : Word_32) return Word_32 is
     (ROTR (X, 7) xor ROTR (X, 18) xor SHR (X, 3));

   function Small_Sigma_1 (X : Word_32) return Word_32 is
     (ROTR (X, 17) xor ROTR (X, 19) xor SHR (X, 10));

   type Words_32 is array (Natural range <>) of Word_32;

   --  4.2.2: the sixty-four SHA-256 constants K{256}_0 .. K{256}_63.
   K_256 : constant Words_32 (0 .. 63) :=
     (16#428A2F98#, 16#71374491#, 16#B5C0FBCF#, 16#E9B5DBA5#,
      16#3956C25B#, 16#59F111F1#, 16#923F82A4#, 16#AB1C5ED5#,
      16#D807AA98#, 16#12835B01#, 16#243185BE#, 16#550C7DC3#,
      16#72BE5D74#, 16#80DEB1FE#, 16#9BDC06A7#, 16#C19BF174#,
      16#E49B69C1#, 16#EFBE4786#, 16#0FC19DC6#, 16#240CA1CC#,
      16#2DE92C6F#, 16#4A7484AA#, 16#5CB0A9DC#, 16#76F988DA#,
      16#983E5152#, 16#A831C66D#, 16#B00327C8#, 16#BF597FC7#,
      16#C6E00BF3#, 16#D5A79147#, 16#06CA6351#, 16#14292967#,
      16#27B70A85#, 16#2E1B2138#, 16#4D2C6DFC#, 16#53380D13#,
      16#650A7354#, 16#766A0ABB#, 16#81C2C92E#, 16#92722C85#,
      16#A2BFE8A1#, 16#A81A664B#, 16#C24B8B70#, 16#C76C51A3#,
      16#D192E819#, 16#D6990624#, 16#F40E3585#, 16#106AA070#,
      16#19A4C116#, 16#1E376C08#, 16#2748774C#, 16#34B0BCB5#,
      16#391C0CB3#, 16#4ED8AA4A#, 16#5B9CCA4F#, 16#682E6FF3#,
      16#748F82EE#, 16#78A5636F#, 16#84C87814#, 16#8CC70208#,
      16#90BEFFFA#, 16#A4506CEB#, 16#BEF9A3F7#, 16#C67178F2#);

   --  A hash value H(i): its eight words H(i)_0 .. H(i)_7.
   subtype Hash_Value_256 is Words_32 (0 .. 7);

   --  5.3.3: the initial hash value H(0).
   H0_256 : constant Hash_Value_256 :=
     (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
      16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);

   --  5.1.1: the message's l = 8 * Length bits are followed by the bit 1,
   --  by k zero bits, "where k is the smallest, non-negative solution to
   --  the equation l + 1 + k = 448 mod 512", and by l as a 64-bit block.
   --  With whole bytes, the bit 1 and the first seven of the k bits are
   --  the byte 16#80#, followed by this many zero bytes:
   function Zero_Bytes_256 (Length : Natural) return Natural is
     ((55 - Length) mod 64)
   with Pre => Length <= Maximum_Length;

   --  The padded message's length in bytes, a multiple of 64.
   function Padded_Length_256 (Length : Natural) return Natural is
     (Length + 1 + Zero_Bytes_256 (Length) + 8)
   with Pre => Length <= Maximum_Length;

   --  Byte Index (0 for the most significant) of l = 8 * Length as a
   --  64-bit block.
   function Length_Byte (Length : Natural; Index : Natural) return SMB.Byte
   is
     (SMB.Byte
        ((Interfaces.Unsigned_64 (Length) * 8 / 2 ** (8 * (7 - Index)))
         mod 256))
   with Pre => Length <= Maximum_Length and then Index < 8;

   --  Byte Index of the padded message.
   function Padded_Byte_256
     (Message : SMB.Bytes; Index : Natural) return SMB.Byte
   is
     (if Index < Message'Length then Message (Message'First + Index)
      elsif Index = Message'Length then 16#80#
      elsif Index < Message'Length + 1 + Zero_Bytes_256 (Message'Length)
      then 0
      else
        Length_Byte
          (Message'Length,
           Index - (Message'Length + 1 + Zero_Bytes_256 (Message'Length))))
   with Pre =>
     Message'Length <= Maximum_Length
     and then Index < Padded_Length_256 (Message'Length);

   subtype Block_256 is SMB.Bytes (0 .. 63);

   --  5.2.1: block M(N + 1) (the standard counts from 1) of the padded
   --  message, as its 64 bytes.
   function Padded_Block_256
     (Message : SMB.Bytes; N : Natural) return Block_256
   is
     (for Index in Block_256'Range =>
        Padded_Byte_256 (Message, 64 * N + Index))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N < Padded_Length_256 (Message'Length) / 64;

   --  5.2.1: word M(i)_J of a block, from its bytes 4J .. 4J + 3.
   function Block_Word (Block : Block_256; J : Natural) return Word_32 is
     (Word_32 (Block (4 * J)) * 2 ** 24
      + Word_32 (Block (4 * J + 1)) * 2 ** 16
      + Word_32 (Block (4 * J + 2)) * 2 ** 8
      + Word_32 (Block (4 * J + 3)))
   with Pre => J < 16;

   --  6.2.2 step 1, the message schedule W_0 .. W_63:
   --    W_t = M(i)_t                                            0 <= t <= 15
   --    W_t = s1 (W_t-2) + W_t-7 + s0 (W_t-15) + W_t-16        16 <= t <= 63
   --  (s0 and s1 the small sigmas). Schedule_Prefix_256 (Block, T) holds
   --  W_0 .. W_T-1 and zeros after them.
   subtype Schedule_256 is Words_32 (0 .. 63);

   function Schedule_Prefix_256
     (Block : Block_256; T : Natural) return Schedule_256
   is
     (if T = 16
      then (for J in Schedule_256'Range =>
              (if J < 16 then Block_Word (Block, J) else 0))
      else
        (declare
            W : constant Schedule_256 := Schedule_Prefix_256 (Block, T - 1);
         begin
            (W with delta T - 1 =>
               Small_Sigma_1 (W (T - 3)) + W (T - 8)
               + Small_Sigma_0 (W (T - 16)) + W (T - 17))))
   with Pre => T in 16 .. 64,
     Subprogram_Variant => (Decreases => T);

   function Message_Schedule_256 (Block : Block_256) return Schedule_256 is
     (Schedule_Prefix_256 (Block, 64));

   --  The working variables a .. h.
   type Working_32 is record
      A, B, C, D, E, F, G, H : Word_32;
   end record;

   --  6.2.2 step 3, for one t:
   --    T1 = h + S1 (e) + Ch (e, f, g) + K_t + W_t
   --    T2 = S0 (a) + Maj (a, b, c)
   --    h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
   --  (S0 and S1 the big sigmas).
   function Round_256 (V : Working_32; K, W : Word_32) return Working_32 is
     (declare
         T1 : constant Word_32 :=
           V.H + Big_Sigma_1 (V.E) + Ch (V.E, V.F, V.G) + K + W;
         T2 : constant Word_32 := Big_Sigma_0 (V.A) + Maj (V.A, V.B, V.C);
      begin
         (A => T1 + T2, B => V.A, C => V.B, D => V.C,
          E => V.D + T1, F => V.E, G => V.F, H => V.G));

   --  Step 2, the working variables from H(i-1), and step 3 for t = 0 ..
   --  T - 1.
   function Rounds_256
     (H : Hash_Value_256; W : Schedule_256; T : Natural) return Working_32
   is
     (if T = 0
      then (A => H (0), B => H (1), C => H (2), D => H (3),
            E => H (4), F => H (5), G => H (6), H => H (7))
      else Round_256 (Rounds_256 (H, W, T - 1), K_256 (T - 1), W (T - 1)))
   with Pre => T <= 64,
     Subprogram_Variant => (Decreases => T);

   --  6.2.2, the steps for one block: H(i) from H(i-1) and M(i), step 4
   --  adding the working variables after the 64 rounds to H(i-1).
   function Compress_256
     (H : Hash_Value_256; Block : Block_256) return Hash_Value_256
   is
     (declare
         V : constant Working_32 :=
           Rounds_256 (H, Message_Schedule_256 (Block), 64);
      begin
         (V.A + H (0), V.B + H (1), V.C + H (2), V.D + H (3),
          V.E + H (4), V.F + H (5), V.G + H (6), V.H + H (7)));

   --  6.2.2: H(N) after the first N blocks of the padded message.
   function Hash_Blocks_256
     (Message : SMB.Bytes; N : Natural) return Hash_Value_256
   is
     (if N = 0 then H0_256
      else Compress_256
             (Hash_Blocks_256 (Message, N - 1),
              Padded_Block_256 (Message, N - 1)))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N <= Padded_Length_256 (Message'Length) / 64,
     Subprogram_Variant => (Decreases => N);

   --  Byte Index (0 for the most significant) of a word.
   function Word_Byte (X : Word_32; Index : Natural) return SMB.Byte is
     (SMB.Byte ((X / 2 ** (8 * (3 - Index))) mod 256))
   with Pre => Index < 4;

   subtype Digest_256 is SMB.Bytes (0 .. 31);

   --  6.2.2: the message digest H(N)_0 || H(N)_1 || ... || H(N)_7.
   function Digest_Of_256 (H : Hash_Value_256) return Digest_256 is
     (for Index in Digest_256'Range => Word_Byte (H (Index / 4), Index mod 4));

   --  The digest of a message, from its last block's hash value.
   function SHA256 (Message : SMB.Bytes) return Digest_256 is
     (Digest_Of_256
        (Hash_Blocks_256 (Message, Padded_Length_256 (Message'Length) / 64)))
   with Pre => Message'Length <= Maximum_Length;

   --  A message hashed as it arrives, a byte at a time: not the standard's
   --  words, which state the hash of a whole message, but a model of what
   --  such a computation holds. SMB.Spec.SHA2.Lemmas proves that finishing
   --  it gives SHA256 of the message, and that absorbing two pieces in turn
   --  is absorbing them joined.

   subtype Block_Position_256 is Natural range 0 .. 63;

   --  H(i) after the whole blocks so far, and the next block's first Used
   --  bytes (the bytes after them are whatever the last block left).
   type State_256 is record
      H : Hash_Value_256;
      Block : Block_256;
      Used : Block_Position_256;
   end record;

   Start_256 : constant State_256 :=
     (H => H0_256, Block => (others => 0), Used => 0);

   --  Block with Byte at Position.
   function Put_256
     (Block : Block_256; Position : Block_Position_256; Byte : SMB.Byte)
      return Block_256
   is
     ((Block with delta Position => Byte));

   --  The block, once complete, goes through the hash computation.
   function Absorb_Byte_256 (S : State_256; Byte : SMB.Byte) return State_256
   is
     (if S.Used = 63
      then (H => Compress_256 (S.H, Put_256 (S.Block, S.Used, Byte)),
            Block => Put_256 (S.Block, S.Used, Byte),
            Used => 0)
      else (H => S.H,
            Block => Put_256 (S.Block, S.Used, Byte),
            Used => S.Used + 1));

   --  The first N bytes of Message absorbed after S.
   function Absorb_Prefix_256
     (S : State_256; Message : SMB.Bytes; N : Natural) return State_256
   is
     (if N = 0 then S
      else Absorb_Byte_256
             (Absorb_Prefix_256 (S, Message, N - 1),
              Message (Message'First + (N - 1))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Subprogram_Variant => (Decreases => N);

   function Absorb_256 (S : State_256; Message : SMB.Bytes) return State_256
   is
     (Absorb_Prefix_256 (S, Message, Message'Length))
   with Pre => Message'Length <= Maximum_Length;

   --  5.1.1's padding after Length bytes, which leave the block's first
   --  Used bytes pending: 16#80#, zeros, and the length in the last eight
   --  bytes, in a second block when fewer than nine are left.
   function Pad_Block_256 (S : State_256) return Block_256 is
     (for J in Block_256'Range =>
        (if J < S.Used then S.Block (J)
         elsif J = S.Used then 16#80#
         else 0));

   --  The block with the length: the padded block itself when it has
   --  room, else a block of zeros.
   function Length_Block_256
     (S : State_256; Length : Natural) return Block_256
   is
     (for J in Block_256'Range =>
        (if J >= 56 then Length_Byte (Length, J - 56)
         elsif S.Used < 56 then Pad_Block_256 (S) (J)
         else 0))
   with Pre => Length <= Maximum_Length;

   --  The hash value before the block with the length.
   function Before_Length_256 (S : State_256) return Hash_Value_256 is
     (if S.Used < 56 then S.H else Compress_256 (S.H, Pad_Block_256 (S)));

   function Finish_256 (S : State_256; Length : Natural) return Digest_256 is
     (Digest_Of_256
        (Compress_256 (Before_Length_256 (S), Length_Block_256 (S, Length))))
   with Pre => Length <= Maximum_Length;

   --  SHA-512, for the SMB 3.1.1 preauth integrity hash: the same steps on
   --  64-bit words, 128-byte blocks and 80 rounds.

   --  2.1: a word of w = 64 bits.
   subtype Word_64 is Interfaces.Unsigned_64;

   --  2.2.2 and 3.2, for w = 64.
   function SHR (X : Word_64; N : Natural) return Word_64 is
     (Interfaces.Shift_Right (X, N))
   with Pre => N < 64;

   function ROTR (X : Word_64; N : Natural) return Word_64 is
     (Interfaces.Shift_Right (X, N) or Interfaces.Shift_Left (X, 64 - N))
   with Pre => N < 64;

   --  4.1.3: the SHA-512 functions.
   function Ch (X, Y, Z : Word_64) return Word_64 is
     ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word_64) return Word_64 is
     ((X and Y) xor (X and Z) xor (Y and Z));

   function Big_Sigma_0 (X : Word_64) return Word_64 is
     (ROTR (X, 28) xor ROTR (X, 34) xor ROTR (X, 39));

   function Big_Sigma_1 (X : Word_64) return Word_64 is
     (ROTR (X, 14) xor ROTR (X, 18) xor ROTR (X, 41));

   function Small_Sigma_0 (X : Word_64) return Word_64 is
     (ROTR (X, 1) xor ROTR (X, 8) xor SHR (X, 7));

   function Small_Sigma_1 (X : Word_64) return Word_64 is
     (ROTR (X, 19) xor ROTR (X, 61) xor SHR (X, 6));

   type Words_64 is array (Natural range <>) of Word_64;

   --  4.2.3: the eighty SHA-512 constants K{512}_0 .. K{512}_79.
   K_512 : constant Words_64 (0 .. 79) :=
     (16#428A2F98D728AE22#, 16#7137449123EF65CD#, 16#B5C0FBCFEC4D3B2F#,
      16#E9B5DBA58189DBBC#, 16#3956C25BF348B538#, 16#59F111F1B605D019#,
      16#923F82A4AF194F9B#, 16#AB1C5ED5DA6D8118#, 16#D807AA98A3030242#,
      16#12835B0145706FBE#, 16#243185BE4EE4B28C#, 16#550C7DC3D5FFB4E2#,
      16#72BE5D74F27B896F#, 16#80DEB1FE3B1696B1#, 16#9BDC06A725C71235#,
      16#C19BF174CF692694#, 16#E49B69C19EF14AD2#, 16#EFBE4786384F25E3#,
      16#0FC19DC68B8CD5B5#, 16#240CA1CC77AC9C65#, 16#2DE92C6F592B0275#,
      16#4A7484AA6EA6E483#, 16#5CB0A9DCBD41FBD4#, 16#76F988DA831153B5#,
      16#983E5152EE66DFAB#, 16#A831C66D2DB43210#, 16#B00327C898FB213F#,
      16#BF597FC7BEEF0EE4#, 16#C6E00BF33DA88FC2#, 16#D5A79147930AA725#,
      16#06CA6351E003826F#, 16#142929670A0E6E70#, 16#27B70A8546D22FFC#,
      16#2E1B21385C26C926#, 16#4D2C6DFC5AC42AED#, 16#53380D139D95B3DF#,
      16#650A73548BAF63DE#, 16#766A0ABB3C77B2A8#, 16#81C2C92E47EDAEE6#,
      16#92722C851482353B#, 16#A2BFE8A14CF10364#, 16#A81A664BBC423001#,
      16#C24B8B70D0F89791#, 16#C76C51A30654BE30#, 16#D192E819D6EF5218#,
      16#D69906245565A910#, 16#F40E35855771202A#, 16#106AA07032BBD1B8#,
      16#19A4C116B8D2D0C8#, 16#1E376C085141AB53#, 16#2748774CDF8EEB99#,
      16#34B0BCB5E19B48A8#, 16#391C0CB3C5C95A63#, 16#4ED8AA4AE3418ACB#,
      16#5B9CCA4F7763E373#, 16#682E6FF3D6B2B8A3#, 16#748F82EE5DEFB2FC#,
      16#78A5636F43172F60#, 16#84C87814A1F0AB72#, 16#8CC702081A6439EC#,
      16#90BEFFFA23631E28#, 16#A4506CEBDE82BDE9#, 16#BEF9A3F7B2C67915#,
      16#C67178F2E372532B#, 16#CA273ECEEA26619C#, 16#D186B8C721C0C207#,
      16#EADA7DD6CDE0EB1E#, 16#F57D4F7FEE6ED178#, 16#06F067AA72176FBA#,
      16#0A637DC5A2C898A6#, 16#113F9804BEF90DAE#, 16#1B710B35131C471B#,
      16#28DB77F523047D84#, 16#32CAAB7B40C72493#, 16#3C9EBE0A15C9BEBC#,
      16#431D67C49C100D4C#, 16#4CC5D4BECB3E42B6#, 16#597F299CFC657E2A#,
      16#5FCB6FAB3AD6FAEC#, 16#6C44198C4A475817#);

   subtype Hash_Value_512 is Words_64 (0 .. 7);

   --  5.3.5: the initial hash value H(0).
   H0_512 : constant Hash_Value_512 :=
     (16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#, 16#3C6EF372FE94F82B#,
      16#A54FF53A5F1D36F1#, 16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#,
      16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#);

   --  5.1.2: l = 8 * Length bits, the bit 1, k zero bits, "where k is the
   --  smallest non-negative solution to the equation l + 1 + k = 896 mod
   --  1024", and l as a 128-bit block. In bytes, after 16#80#:
   function Zero_Bytes_512 (Length : Natural) return Natural is
     ((111 - Length) mod 128)
   with Pre => Length <= Maximum_Length;

   --  The padded message's length in bytes, a multiple of 128.
   function Padded_Length_512 (Length : Natural) return Natural is
     (Length + 1 + Zero_Bytes_512 (Length) + 16)
   with Pre => Length <= Maximum_Length;

   --  Byte Index (0 for the most significant) of l as a 128-bit block,
   --  whose first eight bytes are zero for every message here.
   function Length_Byte_128 (Length : Natural; Index : Natural) return SMB.Byte
   is
     (if Index < 8 then 0 else Length_Byte (Length, Index - 8))
   with Pre => Length <= Maximum_Length and then Index < 16;

   --  Byte Index of the padded message.
   function Padded_Byte_512
     (Message : SMB.Bytes; Index : Natural) return SMB.Byte
   is
     (if Index < Message'Length then Message (Message'First + Index)
      elsif Index = Message'Length then 16#80#
      elsif Index < Message'Length + 1 + Zero_Bytes_512 (Message'Length)
      then 0
      else
        Length_Byte_128
          (Message'Length,
           Index - (Message'Length + 1 + Zero_Bytes_512 (Message'Length))))
   with Pre =>
     Message'Length <= Maximum_Length
     and then Index < Padded_Length_512 (Message'Length);

   subtype Block_512 is SMB.Bytes (0 .. 127);

   --  5.2.2: block M(N + 1) of the padded message, as its 128 bytes.
   function Padded_Block_512
     (Message : SMB.Bytes; N : Natural) return Block_512
   is
     (for Index in Block_512'Range =>
        Padded_Byte_512 (Message, 128 * N + Index))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N < Padded_Length_512 (Message'Length) / 128;

   --  5.2.2: word M(i)_J of a block, from its bytes 8J .. 8J + 7.
   function Block_Word_64 (Block : Block_512; J : Natural) return Word_64 is
     (Word_64 (Block (8 * J)) * 2 ** 56
      + Word_64 (Block (8 * J + 1)) * 2 ** 48
      + Word_64 (Block (8 * J + 2)) * 2 ** 40
      + Word_64 (Block (8 * J + 3)) * 2 ** 32
      + Word_64 (Block (8 * J + 4)) * 2 ** 24
      + Word_64 (Block (8 * J + 5)) * 2 ** 16
      + Word_64 (Block (8 * J + 6)) * 2 ** 8
      + Word_64 (Block (8 * J + 7)))
   with Pre => J < 16;

   --  6.4.2 step 1, the message schedule W_0 .. W_79:
   --    W_t = M(i)_t                                            0 <= t <= 15
   --    W_t = s1 (W_t-2) + W_t-7 + s0 (W_t-15) + W_t-16        16 <= t <= 79
   subtype Schedule_512 is Words_64 (0 .. 79);

   function Schedule_Prefix_512
     (Block : Block_512; T : Natural) return Schedule_512
   is
     (if T = 16
      then (for J in Schedule_512'Range =>
              (if J < 16 then Block_Word_64 (Block, J) else 0))
      else
        (declare
            W : constant Schedule_512 := Schedule_Prefix_512 (Block, T - 1);
         begin
            (W with delta T - 1 =>
               Small_Sigma_1 (W (T - 3)) + W (T - 8)
               + Small_Sigma_0 (W (T - 16)) + W (T - 17))))
   with Pre => T in 16 .. 80,
     Subprogram_Variant => (Decreases => T);

   function Message_Schedule_512 (Block : Block_512) return Schedule_512 is
     (Schedule_Prefix_512 (Block, 80));

   type Working_64 is record
      A, B, C, D, E, F, G, H : Word_64;
   end record;

   --  6.4.2 step 3, for one t, as 6.2.2's.
   function Round_512 (V : Working_64; K, W : Word_64) return Working_64 is
     (declare
         T1 : constant Word_64 :=
           V.H + Big_Sigma_1 (V.E) + Ch (V.E, V.F, V.G) + K + W;
         T2 : constant Word_64 := Big_Sigma_0 (V.A) + Maj (V.A, V.B, V.C);
      begin
         (A => T1 + T2, B => V.A, C => V.B, D => V.C,
          E => V.D + T1, F => V.E, G => V.F, H => V.G));

   function Rounds_512
     (H : Hash_Value_512; W : Schedule_512; T : Natural) return Working_64
   is
     (if T = 0
      then (A => H (0), B => H (1), C => H (2), D => H (3),
            E => H (4), F => H (5), G => H (6), H => H (7))
      else Round_512 (Rounds_512 (H, W, T - 1), K_512 (T - 1), W (T - 1)))
   with Pre => T <= 80,
     Subprogram_Variant => (Decreases => T);

   --  6.4.2, the steps for one block.
   function Compress_512
     (H : Hash_Value_512; Block : Block_512) return Hash_Value_512
   is
     (declare
         V : constant Working_64 :=
           Rounds_512 (H, Message_Schedule_512 (Block), 80);
      begin
         (V.A + H (0), V.B + H (1), V.C + H (2), V.D + H (3),
          V.E + H (4), V.F + H (5), V.G + H (6), V.H + H (7)));

   --  6.4.2: H(N) after the first N blocks of the padded message.
   function Hash_Blocks_512
     (Message : SMB.Bytes; N : Natural) return Hash_Value_512
   is
     (if N = 0 then H0_512
      else Compress_512
             (Hash_Blocks_512 (Message, N - 1),
              Padded_Block_512 (Message, N - 1)))
   with Pre =>
     Message'Length <= Maximum_Length
     and then N <= Padded_Length_512 (Message'Length) / 128,
     Subprogram_Variant => (Decreases => N);

   --  Byte Index (0 for the most significant) of a 64-bit word.
   function Word_Byte (X : Word_64; Index : Natural) return SMB.Byte is
     (SMB.Byte ((X / 2 ** (8 * (7 - Index))) mod 256))
   with Pre => Index < 8;

   subtype Digest_512 is SMB.Bytes (0 .. 63);

   --  6.4.2: the message digest H(N)_0 || H(N)_1 || ... || H(N)_7.
   function Digest_Of_512 (H : Hash_Value_512) return Digest_512 is
     (for Index in Digest_512'Range => Word_Byte (H (Index / 8), Index mod 8));

   function SHA512 (Message : SMB.Bytes) return Digest_512 is
     (Digest_Of_512
        (Hash_Blocks_512
           (Message, Padded_Length_512 (Message'Length) / 128)))
   with Pre => Message'Length <= Maximum_Length;

   --  SHA-512's message hashed as it arrives, as SHA-256's.

   subtype Block_Position_512 is Natural range 0 .. 127;

   type State_512 is record
      H : Hash_Value_512;
      Block : Block_512;
      Used : Block_Position_512;
   end record;

   Start_512 : constant State_512 :=
     (H => H0_512, Block => (others => 0), Used => 0);

   function Put_512
     (Block : Block_512; Position : Block_Position_512; Byte : SMB.Byte)
      return Block_512
   is
     ((Block with delta Position => Byte));

   function Absorb_Byte_512 (S : State_512; Byte : SMB.Byte) return State_512
   is
     (if S.Used = 127
      then (H => Compress_512 (S.H, Put_512 (S.Block, S.Used, Byte)),
            Block => Put_512 (S.Block, S.Used, Byte),
            Used => 0)
      else (H => S.H,
            Block => Put_512 (S.Block, S.Used, Byte),
            Used => S.Used + 1));

   function Absorb_Prefix_512
     (S : State_512; Message : SMB.Bytes; N : Natural) return State_512
   is
     (if N = 0 then S
      else Absorb_Byte_512
             (Absorb_Prefix_512 (S, Message, N - 1),
              Message (Message'First + (N - 1))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Subprogram_Variant => (Decreases => N);

   function Absorb_512 (S : State_512; Message : SMB.Bytes) return State_512
   is
     (Absorb_Prefix_512 (S, Message, Message'Length))
   with Pre => Message'Length <= Maximum_Length;

   --  5.1.2's padding after Length bytes: 16#80#, zeros, and the length in
   --  the last sixteen bytes, in a second block when fewer than seventeen
   --  are left.
   function Pad_Block_512 (S : State_512) return Block_512 is
     (for J in Block_512'Range =>
        (if J < S.Used then S.Block (J)
         elsif J = S.Used then 16#80#
         else 0));

   function Length_Block_512
     (S : State_512; Length : Natural) return Block_512
   is
     (for J in Block_512'Range =>
        (if J >= 112 then Length_Byte_128 (Length, J - 112)
         elsif S.Used < 112 then Pad_Block_512 (S) (J)
         else 0))
   with Pre => Length <= Maximum_Length;

   function Before_Length_512 (S : State_512) return Hash_Value_512 is
     (if S.Used < 112 then S.H else Compress_512 (S.H, Pad_Block_512 (S)));

   function Finish_512 (S : State_512; Length : Natural) return Digest_512 is
     (Digest_Of_512
        (Compress_512 (Before_Length_512 (S), Length_Block_512 (S, Length))))
   with Pre => Length <= Maximum_Length;
end SMB.Spec.SHA2;
