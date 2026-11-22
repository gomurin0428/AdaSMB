--  Proof only: no build generates code for these lemmas (smb.gpr compiles
--  the unit to an empty object), and only ignored code calls them. Like
--  every source, it must still compile with each GNAT the crate supports.
pragma Assertion_Policy (Ghost => Ignore);

--  Lemmas about SMB.Spec.MD5, for the proofs of the code that hashes, as
--  SMB.Spec.SHA2.Lemmas's for SHA-256: its functions give equal results on
--  equal blocks, absorbing two pieces in turn is absorbing them joined, and
--  finishing what absorbed a message from the start gives MD5 of the
--  message. A buffer is a record of words, which the provers compare as
--  values, so only blocks need the congruence lemmas.
package SMB.Spec.MD5.Lemmas
  with Ghost, SPARK_Mode
is
   use type SMB.Byte;

   --  Congruence. Ada's "=" on arrays compares their elements, and the
   --  provers do not put one array for another equal to it that way; these
   --  lemmas carry such an equality through the specification's functions.

   procedure Lemma_Operations_Equal (V : Buffer; X, Y : Block; N : Natural)
   with Global => null,
     Pre => X = Y and then N <= 64,
     Post => Operations (V, X, N) = Operations (V, Y, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Compress_Equal (V : Buffer; X, Y : Block)
   with Global => null,
     Pre => X = Y,
     Post => Compress (V, X) = Compress (V, Y);

   procedure Lemma_Absorb_Byte_Equal (S1, S2 : State; Byte : SMB.Byte)
   with Global => null,
     Pre => S1 = S2,
     Post => Absorb_Byte (S1, Byte) = Absorb_Byte (S2, Byte);

   procedure Lemma_Absorb_Equal
     (S1, S2 : State; Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length
       and then S1 = S2,
     Post => Absorb_Prefix (S1, Message, N) =
       Absorb_Prefix (S2, Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Finish_Equal (S1, S2 : State; Length : Natural)
   with Global => null,
     Pre => S1 = S2 and then Length <= Maximum_Length,
     Post => Finish (S1, Length) = Finish (S2, Length);

   --  The recursive definitions unfolded once.

   procedure Lemma_Absorb_None (S : State; Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Absorb_Prefix (S, Message, 0) = S;

   procedure Lemma_Absorb_Unfold
     (S : State; Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Absorb_Prefix (S, Message, N) =
       Absorb_Byte
         (Absorb_Prefix (S, Message, N - 1),
          Message (Message'First + (N - 1)));

   procedure Lemma_Hash_Blocks_Unfold (Message : SMB.Bytes; N : Positive)
   with Global => null,
     Pre => Message'Length <= Maximum_Length
       and then N <= Padded_Length (Message'Length) / 64,
     Post => Hash_Blocks (Message, N) =
       Compress
         (Hash_Blocks (Message, N - 1), Padded_Block (Message, N - 1));

   --  Two pieces absorbed in turn are the two joined.

   procedure Lemma_Absorb_Join_Start
     (S : State; A, B : SMB.Bytes; K : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then K <= A'Length,
     Post => Absorb_Prefix (S, A & B, K) = Absorb_Prefix (S, A, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_Absorb_Join_Rest
     (S : State; A, B : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length
       and then N <= B'Length,
     Post => Absorb_Prefix (S, A & B, A'Length + N) =
       Absorb_Prefix (Absorb (S, A), B, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Absorb_Join (S : State; A, B : SMB.Bytes)
   with Global => null,
     Pre => A'Length + B'Length <= Maximum_Length
       and then A'First <= Natural'Last - Maximum_Length,
     Post => Absorb (Absorb (S, A), B) = Absorb (S, A & B);

   --  What the first N bytes of Message absorbed from the start hold: the
   --  hash value after their whole blocks, and the bytes after those.
   function Holds
     (S : State; Message : SMB.Bytes; N : Natural) return Boolean
   is
     (S.Used = N mod 64
      and then S.Value = Hash_Blocks (Message, N / 64)
      and then (for all J in 0 .. S.Used - 1 =>
                  S.Pending (J) = Message (Message'First + (N - S.Used + J))))
   with Pre => Message'Length <= Maximum_Length and then N <= Message'Length;

   procedure Lemma_Absorb_Holds (Message : SMB.Bytes; N : Natural)
   with Global => null,
     Pre => Message'Length <= Maximum_Length and then N <= Message'Length,
     Post => Holds (Absorb_Prefix (Start, Message, N), Message, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Finish (Message : SMB.Bytes)
   with Global => null,
     Pre => Message'Length <= Maximum_Length,
     Post => Finish (Absorb (Start, Message), Message'Length) =
       MD5 (Message);
end SMB.Spec.MD5.Lemmas;
