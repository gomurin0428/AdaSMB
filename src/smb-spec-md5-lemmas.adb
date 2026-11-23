--  Proof only: no build generates code for these lemmas (smb.gpr compiles
--  the unit to an empty object), and only ignored code calls them. Like
--  every source, it must still compile with each GNAT the crate supports.
pragma Assertion_Policy (Ghost => Ignore);

package body SMB.Spec.MD5.Lemmas
  with SPARK_Mode
is
   procedure Lemma_Operations_Equal (V : Buffer; X, Y : Block; N : Natural)
   is
   begin
      if N > 0 then
         Lemma_Operations_Equal (V, X, Y, N - 1);
      end if;
   end Lemma_Operations_Equal;

   procedure Lemma_Compress_Equal (V : Buffer; X, Y : Block) is
   begin
      Lemma_Operations_Equal (V, X, Y, 64);
   end Lemma_Compress_Equal;

   procedure Lemma_Absorb_Byte_Equal (S1, S2 : State; Byte : SMB.Byte) is
      X1 : constant Block := Put (S1.Pending, S1.Used, Byte);
      X2 : constant Block := Put (S2.Pending, S2.Used, Byte);
   begin
      pragma Assert (X1 = X2);
      if S1.Used = 63 then
         Lemma_Compress_Equal (S1.Value, X1, X2);
         pragma Assert
           (Absorb_Byte (S1, Byte) = (Value => Compress (S1.Value, X1),
                                          Pending => X1, Used => 0));
         pragma Assert
           (Absorb_Byte (S2, Byte) = (Value => Compress (S2.Value, X2),
                                          Pending => X2, Used => 0));
      else
         pragma Assert
           (Absorb_Byte (S1, Byte) =
              (Value => S1.Value, Pending => X1, Used => S1.Used + 1));
         pragma Assert
           (Absorb_Byte (S2, Byte) =
              (Value => S2.Value, Pending => X2, Used => S2.Used + 1));
      end if;
   end Lemma_Absorb_Byte_Equal;

   procedure Lemma_Absorb_Equal
     (S1, S2 : State; Message : SMB.Bytes; N : Natural) is
   begin
      if N > 0 then
         Lemma_Absorb_Equal (S1, S2, Message, N - 1);
         Lemma_Absorb_Byte_Equal
           (Absorb_Prefix (S1, Message, N - 1),
            Absorb_Prefix (S2, Message, N - 1),
            Message (Message'First + (N - 1)));
      end if;
   end Lemma_Absorb_Equal;

   procedure Lemma_Finish_Equal (S1, S2 : State; Length : Natural) is
   begin
      pragma Assert (Pad_Block (S1) = Pad_Block (S2));
      Lemma_Compress_Equal (S1.Value, Pad_Block (S1), Pad_Block (S2));
      pragma Assert (Before_Length (S1) = Before_Length (S2));
      pragma Assert
        (Length_Block (S1, Length) = Length_Block (S2, Length));
      Lemma_Compress_Equal
        (Before_Length (S1), Length_Block (S1, Length),
         Length_Block (S2, Length));
   end Lemma_Finish_Equal;

   procedure Lemma_Absorb_None (S : State; Message : SMB.Bytes) is null;

   procedure Lemma_Absorb_Unfold
     (S : State; Message : SMB.Bytes; N : Positive) is null;

   procedure Lemma_Hash_Blocks_Unfold (Message : SMB.Bytes; N : Positive)
   is null;

   procedure Lemma_Absorb_Join_Start
     (S : State; A, B : SMB.Bytes; K : Natural)
   is
      AB : constant SMB.Bytes := A & B;
   begin
      if K > 0 then
         Lemma_Absorb_Join_Start (S, A, B, K - 1);
         pragma Assert (AB'First = A'First);
         pragma Assert (AB (AB'First + (K - 1)) = A (A'First + (K - 1)));
         Lemma_Absorb_Unfold (S, AB, K);
         Lemma_Absorb_Unfold (S, A, K);
         Lemma_Absorb_Byte_Equal
           (Absorb_Prefix (S, A & B, K - 1),
            Absorb_Prefix (S, A, K - 1),
            A (A'First + (K - 1)));
      end if;
   end Lemma_Absorb_Join_Start;

   procedure Lemma_Absorb_Join_Rest
     (S : State; A, B : SMB.Bytes; N : Natural)
   is
      AB : constant SMB.Bytes := A & B;
   begin
      if N = 0 then
         Lemma_Absorb_Join_Start (S, A, B, A'Length);
      else
         Lemma_Absorb_Join_Rest (S, A, B, N - 1);
         pragma Assert
           (AB (AB'First + (A'Length + (N - 1))) = B (B'First + (N - 1)));
         Lemma_Absorb_Unfold (S, AB, A'Length + N);
         Lemma_Absorb_Unfold (Absorb (S, A), B, N);
         Lemma_Absorb_Byte_Equal
           (Absorb_Prefix (S, A & B, A'Length + (N - 1)),
            Absorb_Prefix (Absorb (S, A), B, N - 1),
            B (B'First + (N - 1)));
      end if;
   end Lemma_Absorb_Join_Rest;

   procedure Lemma_Absorb_Join (S : State; A, B : SMB.Bytes) is
   begin
      Lemma_Absorb_Join_Rest (S, A, B, B'Length);
   end Lemma_Absorb_Join;

   procedure Lemma_Absorb_Holds (Message : SMB.Bytes; N : Natural) is
   begin
      if N > 0 then
         Lemma_Absorb_Holds (Message, N - 1);
         declare
            Before : constant State :=
              Absorb_Prefix (Start, Message, N - 1);
            Byte : constant SMB.Byte := Message (Message'First + (N - 1));
            K : constant Natural := (N - 1) / 64;
            X : constant Block :=
              Put (Before.Pending, Before.Used, Byte);
            After : constant State := Absorb_Byte (Before, Byte);
         begin
            pragma Assert (Before.Value = Hash_Blocks (Message, K));
            if Before.Used = 63 then
               pragma Assert (X = Padded_Block (Message, K));
               Lemma_Compress_Equal
                 (Before.Value, X, Padded_Block (Message, K));
               pragma Assert (N / 64 = K + 1);
               Lemma_Hash_Blocks_Unfold (Message, K + 1);
               pragma Assert (After.Value = Compress (Before.Value, X));
               pragma Assert (After.Value = Hash_Blocks (Message, N / 64));
            else
               pragma Assert (N / 64 = K);
               pragma Assert (After.Value = Hash_Blocks (Message, N / 64));
            end if;
            pragma Assert (Holds (After, Message, N));
            Lemma_Absorb_Unfold (Start, Message, N);
            pragma Assert (Absorb_Prefix (Start, Message, N) = After);
         end;
      end if;
   end Lemma_Absorb_Holds;

   procedure Lemma_Finish (Message : SMB.Bytes) is
      L : constant Natural := Message'Length;
      Q : constant Natural := L / 64;
      S : constant State := Absorb (Start, Message);
   begin
      Lemma_Absorb_Holds (Message, L);
      pragma Assert (S.Used = L mod 64 and then L = 64 * Q + S.Used);
      pragma Assert (S.Value = Hash_Blocks (Message, Q));
      if S.Used < 56 then
         pragma Assert (Zero_Bytes (L) = 55 - S.Used);
         pragma Assert (Padded_Length (L) / 64 = Q + 1);
         pragma Assert
           (Length_Block (S, L) = Padded_Block (Message, Q));
         Lemma_Compress_Equal
           (S.Value, Length_Block (S, L), Padded_Block (Message, Q));
         Lemma_Hash_Blocks_Unfold (Message, Q + 1);
         pragma Assert
           (Compress (Before_Length (S), Length_Block (S, L)) =
              Hash_Blocks (Message, Q + 1));
      else
         pragma Assert (Zero_Bytes (L) = 119 - S.Used);
         pragma Assert (Padded_Length (L) / 64 = Q + 2);
         pragma Assert (Pad_Block (S) = Padded_Block (Message, Q));
         Lemma_Compress_Equal
           (S.Value, Pad_Block (S), Padded_Block (Message, Q));
         Lemma_Hash_Blocks_Unfold (Message, Q + 1);
         pragma Assert
           (Before_Length (S) = Hash_Blocks (Message, Q + 1));
         pragma Assert
           (Length_Block (S, L) = Padded_Block (Message, Q + 1));
         Lemma_Compress_Equal
           (Before_Length (S), Length_Block (S, L),
            Padded_Block (Message, Q + 1));
         Lemma_Hash_Blocks_Unfold (Message, Q + 2);
         pragma Assert
           (Compress (Before_Length (S), Length_Block (S, L)) =
              Hash_Blocks (Message, Q + 2));
      end if;
   end Lemma_Finish;
end SMB.Spec.MD5.Lemmas;
