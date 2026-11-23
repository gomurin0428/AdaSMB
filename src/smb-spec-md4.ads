with Interfaces;
with SMB.Spec.MD5;

--  The MD4 Message-Digest Algorithm (RFC 1320, April 1992), which NTLM uses
--  for the NT one-way function (MD4 of the password in UTF-16LE). Section
--  numbers are the RFC's. Its steps 1 to 3 (the padding, the length, the
--  buffer) and its words are RFC 1321's for MD5 word for word, so they are
--  SMB.Spec.MD5's; step 4's three rounds are MD4's own.
package SMB.Spec.MD4
  with Ghost, SPARK_Mode
is
   use type Interfaces.Unsigned_32;
   package MD5 renames SMB.Spec.MD5;
   subtype Word is MD5.Word;

   --  3.4: the auxiliary functions F (as MD5's), G and H.
   function F (X, Y, Z : Word) return Word is ((X and Y) or ((not X) and Z));
   function G (X, Y, Z : Word) return Word is
     ((X and Y) or (X and Z) or (Y and Z));
   function H (X, Y, Z : Word) return Word is (X xor Y xor Z);

   --  3.4's 48 operations [abcd k s], in order: the word k and the shift s
   --  of each (rounds 1 to 3, sixteen each).
   K_Index : constant array (0 .. 47) of Natural :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
      0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);

   Shift : constant array (0 .. 47) of Natural :=
     (3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
      3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
      3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15);

   --  The operation's function and added constant: round 1 "a = (a +
   --  F(b,c,d) + X[k]) <<< s", round 2 "a = (a + G(b,c,d) + X[k] +
   --  5A827999) <<< s", round 3 "a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<<
   --  s".
   function Round_Value (Step : Natural; X, Y, Z : Word) return Word is
     (case Step / 16 is
         when 0 => F (X, Y, Z),
         when 1 => G (X, Y, Z) + 16#5A82_7999#,
         when others => H (X, Y, Z) + 16#6ED9_EBA1#)
   with Pre => Step < 48;

   --  Operation Step (0 .. 47): the RFC names the next operation's words
   --  turned (ABCD, DABC, CDAB, BCDA); here the buffer turns instead, as in
   --  SMB.Spec.MD5.
   function Operation
     (V : MD5.Buffer; Step : Natural; X : Word) return MD5.Buffer
   is
     (A => V.D,
      B => MD5.Rotate_Left
             (V.A + Round_Value (Step, V.B, V.C, V.D) + X, Shift (Step)),
      C => V.B,
      D => V.C)
   with Pre => Step < 48;

   function Operations
     (V : MD5.Buffer; B : MD5.Block; N : Natural) return MD5.Buffer
   is
     (if N = 0 then V
      else Operation
             (Operations (V, B, N - 1), N - 1,
              MD5.Block_Word (B, K_Index (N - 1))))
   with Pre => N <= 48,
     Subprogram_Variant => (Decreases => N);

   --  3.4, a block: "A = A + AA, B = B + BB, C = C + CC, D = D + DD".
   function Compress (V : MD5.Buffer; B : MD5.Block) return MD5.Buffer is
     (declare
         R : constant MD5.Buffer := Operations (V, B, 48);
      begin
         (A => R.A + V.A, B => R.B + V.B, C => R.C + V.C, D => R.D + V.D));

   function Hash_Blocks (Message : SMB.Bytes; N : Natural) return MD5.Buffer
   is
     (if N = 0 then MD5.Initial
      else Compress
             (Hash_Blocks (Message, N - 1), MD5.Padded_Block (Message, N - 1)))
   with Pre =>
     Message'Length <= MD5.Maximum_Length
     and then N <= MD5.Padded_Length (Message'Length) / 64,
     Subprogram_Variant => (Decreases => N);

   --  3.5: the digest A, B, C, D, "beginning with the low-order byte of A".
   function MD4 (Message : SMB.Bytes) return MD5.Digest is
     (MD5.Digest_Of
        (Hash_Blocks (Message, MD5.Padded_Length (Message'Length) / 64)))
   with Pre => Message'Length <= MD5.Maximum_Length;
end SMB.Spec.MD4;
