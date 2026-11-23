--  Proof only: no build generates code for these lemmas (smb.gpr compiles
--  the unit to an empty object), and only ignored code calls them. Like
--  every source, it must still compile with each GNAT the crate supports.
pragma Assertion_Policy (Ghost => Ignore);

--  Lemmas about SMB.Spec.SHA2, for the proofs of the code that hashes:
--  its functions give equal results on equal arguments, absorbing two
--  pieces in turn is absorbing them joined, and finishing what absorbed a
--  message from the start gives its digest (SHA256 or SHA512).
package SMB.Spec.SHA2.Lemmas
  with Ghost, SPARK_Mode
is
   use type SMB.Byte;

   --  Congruence. Ada's "=" on arrays compares their elements, and the
   --  provers do not put one array for another equal to it that way; these
   --  lemmas carry such an equality through the specification's functions.

   procedure Lemma_Schedule_Equal (X, Y : Block_256; T : Natural)
   with Global => null,
     Pre => X = Y and then T in 16 .. 64,
     Post => Schedule_Prefix_256 (X, T) = Schedule_Prefix_256 (Y, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Rounds_Equal
     (H1, H2 : Hash_Value_256; W1, W2 : Schedule_256; T : Natural)
   with Global => null,
     Pre => H1 = H2 and then W1 = W2 and then T <= 64,
     Post => Rounds_256 (H1, W1, T) = Rounds_256 (H2, W2, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Compress_Equal (H1, H2 : Hash_Value_256; X, Y : Block_256)
   with Global => null,
     Pre => H1 = H2 and then X = Y,
     Post => Compress_256 (H1, X) = Compress_256 (H2, Y);

   procedure Lemma_Absorb_Byte_Equal (S1, S2 : State_256; Byte : SMB.Byte)
   with Global => null,
     Pre => S1 = S2,
     Post => Absorb_Byte_256 (S1, Byte) = Absorb_Byte_256 (S2, Byte);

   procedure Lemma_Absorb_Equal
     (S1, S2 : State_256; Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length
       and then S1 = S2,
     Post => Absorb_Prefix_256 (S1, Message, N) =
       Absorb_Prefix_256 (S2, Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Finish_Equal (S1, S2 : State_256; Length : Natural)
   with Global => null,
     Pre => S1 = S2 and then Length <= Maximum_Length,
     Post => Finish_256 (S1, Length) = Finish_256 (S2, Length);

   --  The recursive definitions unfolded once.

   procedure Lemma_Absorb_None (S : State_256; Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Absorb_Prefix_256 (S, Message, 0) = S;

   procedure Lemma_Absorb_Unfold
     (S : State_256; Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Absorb_Prefix_256 (S, Message, N) =
       Absorb_Byte_256
         (Absorb_Prefix_256 (S, Message, N - 1),
          Message (Message'First + (N - 1)));

   procedure Lemma_Hash_Blocks_Unfold (Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length
       and then N <= Padded_Length_256 (Message'Length) / 64,
     Post => Hash_Blocks_256 (Message, N) =
       Compress_256
         (Hash_Blocks_256 (Message, N - 1), Padded_Block_256 (Message, N - 1));

   --  Two pieces absorbed in turn are the two joined.

   procedure Lemma_Absorb_Join_Start
     (S : State_256; A, B : SMB.Bytes; K : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then K <= A'Length,
     Post => Absorb_Prefix_256 (S, A & B, K) = Absorb_Prefix_256 (S, A, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_Absorb_Join_Rest
     (S : State_256; A, B : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then N <= B'Length,
     Post => Absorb_Prefix_256 (S, A & B, A'Length + N) =
       Absorb_Prefix_256 (Absorb_256 (S, A), B, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Absorb_Join (S : State_256; A, B : SMB.Bytes)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length,
     Post => Absorb_256 (Absorb_256 (S, A), B) = Absorb_256 (S, A & B);

   --  What the first N bytes of Message absorbed from the start hold: the
   --  hash value after their whole blocks, and the bytes after those.
   function Holds_256
     (S : State_256; Message : SMB.Bytes; N : Natural) return Boolean
   is
     (S.Used = N mod 64
      and then S.H = Hash_Blocks_256 (Message, N / 64)
      and then (for all J in 0 .. S.Used - 1 =>
                  S.Block (J) = Message (Message'First + (N - S.Used + J))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length;

   procedure Lemma_Absorb_Holds (Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Holds_256 (Absorb_Prefix_256 (Start_256, Message, N), Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Finish (Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Finish_256 (Absorb_256 (Start_256, Message), Message'Length) =
       SHA256 (Message);

   --  The same for SHA-512.

   --  Congruence. Ada's "=" on arrays compares their elements, and the
   --  provers do not put one array for another equal to it that way; these
   --  lemmas carry such an equality through the specification's functions.

   procedure Lemma_Schedule_Equal_512 (X, Y : Block_512; T : Natural)
   with Global => null,
     Pre => X = Y and then T in 16 .. 80,
     Post => Schedule_Prefix_512 (X, T) = Schedule_Prefix_512 (Y, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Rounds_Equal_512
     (H1, H2 : Hash_Value_512; W1, W2 : Schedule_512; T : Natural)
   with Global => null,
     Pre => H1 = H2 and then W1 = W2 and then T <= 80,
     Post => Rounds_512 (H1, W1, T) = Rounds_512 (H2, W2, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Compress_Equal_512
     (H1, H2 : Hash_Value_512; X, Y : Block_512)
   with Global => null,
     Pre => H1 = H2 and then X = Y,
     Post => Compress_512 (H1, X) = Compress_512 (H2, Y);

   procedure Lemma_Absorb_Byte_Equal_512
     (S1, S2 : State_512; Byte : SMB.Byte)
   with Global => null,
     Pre => S1 = S2,
     Post => Absorb_Byte_512 (S1, Byte) = Absorb_Byte_512 (S2, Byte);

   procedure Lemma_Absorb_Equal_512
     (S1, S2 : State_512; Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length
       and then S1 = S2,
     Post => Absorb_Prefix_512 (S1, Message, N) =
       Absorb_Prefix_512 (S2, Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Finish_Equal_512 (S1, S2 : State_512; Length : Natural)
   with Global => null,
     Pre => S1 = S2 and then Length <= Maximum_Length,
     Post => Finish_512 (S1, Length) = Finish_512 (S2, Length);

   --  The recursive definitions unfolded once.

   procedure Lemma_Absorb_None_512 (S : State_512; Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Absorb_Prefix_512 (S, Message, 0) = S;

   procedure Lemma_Absorb_Unfold_512
     (S : State_512; Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Absorb_Prefix_512 (S, Message, N) =
       Absorb_Byte_512
         (Absorb_Prefix_512 (S, Message, N - 1),
          Message (Message'First + (N - 1)));

   procedure Lemma_Hash_Blocks_Unfold_512 (Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length
       and then N <= Padded_Length_512 (Message'Length) / 128,
     Post => Hash_Blocks_512 (Message, N) =
       Compress_512
         (Hash_Blocks_512 (Message, N - 1), Padded_Block_512 (Message, N - 1));

   --  Two pieces absorbed in turn are the two joined.

   procedure Lemma_Absorb_Join_Start_512
     (S : State_512; A, B : SMB.Bytes; K : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then K <= A'Length,
     Post => Absorb_Prefix_512 (S, A & B, K) = Absorb_Prefix_512 (S, A, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_Absorb_Join_Rest_512
     (S : State_512; A, B : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then N <= B'Length,
     Post => Absorb_Prefix_512 (S, A & B, A'Length + N) =
       Absorb_Prefix_512 (Absorb_512 (S, A), B, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Absorb_Join_512 (S : State_512; A, B : SMB.Bytes)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length,
     Post => Absorb_512 (Absorb_512 (S, A), B) = Absorb_512 (S, A & B);

   --  What the first N bytes of Message absorbed from the start hold: the
   --  hash value after their whole blocks, and the bytes after those.
   function Holds_512
     (S : State_512; Message : SMB.Bytes; N : Natural) return Boolean
   is
     (S.Used = N mod 128
      and then S.H = Hash_Blocks_512 (Message, N / 128)
      and then (for all J in 0 .. S.Used - 1 =>
                  S.Block (J) = Message (Message'First + (N - S.Used + J))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length;

   procedure Lemma_Absorb_Holds_512 (Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Holds_512 (Absorb_Prefix_512 (Start_512, Message, N), Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Digest_Equal_512 (H1, H2 : Hash_Value_512)
   with Global => null,
     Pre => H1 = H2,
     Post => Digest_Of_512 (H1) = Digest_Of_512 (H2);

   procedure Lemma_Finish_512 (Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Finish_512 (Absorb_512 (Start_512, Message), Message'Length) =
       SHA512 (Message);
end SMB.Spec.SHA2.Lemmas;
