--  Proof only: no build generates code for these lemmas (smb.gpr compiles
--  the unit to an empty object), and only ignored code calls them. Like
--  every source, it must still compile with each GNAT the crate supports.
pragma Assertion_Policy (Ghost => Ignore);

package body SMB.Spec.SHA2.Lemmas
  with SPARK_Mode
is
   procedure Lemma_Schedule_Equal (X, Y : Block_256; T : Natural) is
   begin
      if T > 16 then
         Lemma_Schedule_Equal (X, Y, T - 1);
      end if;
   end Lemma_Schedule_Equal;

   procedure Lemma_Rounds_Equal
     (H1, H2 : Hash_Value_256; W1, W2 : Schedule_256; T : Natural) is
   begin
      if T > 0 then
         Lemma_Rounds_Equal (H1, H2, W1, W2, T - 1);
      end if;
   end Lemma_Rounds_Equal;

   procedure Lemma_Compress_Equal (H1, H2 : Hash_Value_256; X, Y : Block_256)
   is
   begin
      Lemma_Schedule_Equal (X, Y, 64);
      Lemma_Rounds_Equal
        (H1, H2, Message_Schedule_256 (X), Message_Schedule_256 (Y), 64);
   end Lemma_Compress_Equal;

   procedure Lemma_Absorb_Byte_Equal (S1, S2 : State_256; Byte : SMB.Byte) is
      X1 : constant Block_256 := Put_256 (S1.Block, S1.Used, Byte);
      X2 : constant Block_256 := Put_256 (S2.Block, S2.Used, Byte);
   begin
      pragma Assert (X1 = X2);
      if S1.Used = 63 then
         Lemma_Compress_Equal (S1.H, S2.H, X1, X2);
         pragma Assert
           (Absorb_Byte_256 (S1, Byte) = (H => Compress_256 (S1.H, X1),
                                          Block => X1, Used => 0));
         pragma Assert
           (Absorb_Byte_256 (S2, Byte) = (H => Compress_256 (S2.H, X2),
                                          Block => X2, Used => 0));
      else
         pragma Assert
           (Absorb_Byte_256 (S1, Byte) =
              (H => S1.H, Block => X1, Used => S1.Used + 1));
         pragma Assert
           (Absorb_Byte_256 (S2, Byte) =
              (H => S2.H, Block => X2, Used => S2.Used + 1));
      end if;
   end Lemma_Absorb_Byte_Equal;

   procedure Lemma_Absorb_Equal
     (S1, S2 : State_256; Message : SMB.Bytes; N : Natural) is
   begin
      if N > 0 then
         Lemma_Absorb_Equal (S1, S2, Message, N - 1);
         Lemma_Absorb_Byte_Equal
           (Absorb_Prefix_256 (S1, Message, N - 1),
            Absorb_Prefix_256 (S2, Message, N - 1),
            Message (Message'First + (N - 1)));
      end if;
   end Lemma_Absorb_Equal;

   procedure Lemma_Finish_Equal (S1, S2 : State_256; Length : Natural) is
   begin
      pragma Assert (Pad_Block_256 (S1) = Pad_Block_256 (S2));
      Lemma_Compress_Equal
        (S1.H, S2.H, Pad_Block_256 (S1), Pad_Block_256 (S2));
      pragma Assert (Before_Length_256 (S1) = Before_Length_256 (S2));
      pragma Assert
        (Length_Block_256 (S1, Length) = Length_Block_256 (S2, Length));
      Lemma_Compress_Equal
        (Before_Length_256 (S1), Before_Length_256 (S2),
         Length_Block_256 (S1, Length), Length_Block_256 (S2, Length));
   end Lemma_Finish_Equal;

   procedure Lemma_Absorb_None (S : State_256; Message : SMB.Bytes) is null;

   procedure Lemma_Absorb_Unfold
     (S : State_256; Message : SMB.Bytes; N : Positive) is null;

   procedure Lemma_Hash_Blocks_Unfold (Message : SMB.Bytes; N : Positive)
   is null;

   procedure Lemma_Absorb_Join_Start
     (S : State_256; A, B : SMB.Bytes; K : Natural)
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
           (Absorb_Prefix_256 (S, A & B, K - 1),
            Absorb_Prefix_256 (S, A, K - 1),
            A (A'First + (K - 1)));
      end if;
   end Lemma_Absorb_Join_Start;

   procedure Lemma_Absorb_Join_Rest
     (S : State_256; A, B : SMB.Bytes; N : Natural)
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
         Lemma_Absorb_Unfold (Absorb_256 (S, A), B, N);
         Lemma_Absorb_Byte_Equal
           (Absorb_Prefix_256 (S, A & B, A'Length + (N - 1)),
            Absorb_Prefix_256 (Absorb_256 (S, A), B, N - 1),
            B (B'First + (N - 1)));
      end if;
   end Lemma_Absorb_Join_Rest;

   procedure Lemma_Absorb_Join (S : State_256; A, B : SMB.Bytes) is
   begin
      Lemma_Absorb_Join_Rest (S, A, B, B'Length);
   end Lemma_Absorb_Join;

   procedure Lemma_Absorb_Holds (Message : SMB.Bytes; N : Natural) is
   begin
      if N > 0 then
         Lemma_Absorb_Holds (Message, N - 1);
         declare
            Before : constant State_256 :=
              Absorb_Prefix_256 (Start_256, Message, N - 1);
            Byte : constant SMB.Byte := Message (Message'First + (N - 1));
            K : constant Natural := (N - 1) / 64;
            X : constant Block_256 :=
              Put_256 (Before.Block, Before.Used, Byte);
            After : constant State_256 := Absorb_Byte_256 (Before, Byte);
         begin
            pragma Assert (Before.H = Hash_Blocks_256 (Message, K));
            if Before.Used = 63 then
               pragma Assert (X = Padded_Block_256 (Message, K));
               Lemma_Compress_Equal
                 (Before.H, Hash_Blocks_256 (Message, K),
                  X, Padded_Block_256 (Message, K));
               pragma Assert (N / 64 = K + 1);
               Lemma_Hash_Blocks_Unfold (Message, K + 1);
               pragma Assert (After.H = Compress_256 (Before.H, X));
               pragma Assert (After.H = Hash_Blocks_256 (Message, N / 64));
            else
               pragma Assert (N / 64 = K);
               pragma Assert (After.H = Hash_Blocks_256 (Message, N / 64));
            end if;
            pragma Assert (Holds_256 (After, Message, N));
            Lemma_Absorb_Unfold (Start_256, Message, N);
            pragma Assert (Absorb_Prefix_256 (Start_256, Message, N) = After);
         end;
      end if;
   end Lemma_Absorb_Holds;

   procedure Lemma_Finish (Message : SMB.Bytes) is
      L : constant Natural := Message'Length;
      Q : constant Natural := L / 64;
      S : constant State_256 := Absorb_256 (Start_256, Message);
   begin
      Lemma_Absorb_Holds (Message, L);
      pragma Assert (S.Used = L mod 64 and then L = 64 * Q + S.Used);
      pragma Assert (S.H = Hash_Blocks_256 (Message, Q));
      if S.Used < 56 then
         pragma Assert (Zero_Bytes_256 (L) = 55 - S.Used);
         pragma Assert (Padded_Length_256 (L) / 64 = Q + 1);
         pragma Assert
           (Length_Block_256 (S, L) = Padded_Block_256 (Message, Q));
         Lemma_Compress_Equal
           (S.H, Hash_Blocks_256 (Message, Q),
            Length_Block_256 (S, L), Padded_Block_256 (Message, Q));
         Lemma_Hash_Blocks_Unfold (Message, Q + 1);
         pragma Assert
           (Compress_256 (Before_Length_256 (S), Length_Block_256 (S, L)) =
              Hash_Blocks_256 (Message, Q + 1));
      else
         pragma Assert (Zero_Bytes_256 (L) = 119 - S.Used);
         pragma Assert (Padded_Length_256 (L) / 64 = Q + 2);
         pragma Assert (Pad_Block_256 (S) = Padded_Block_256 (Message, Q));
         Lemma_Compress_Equal
           (S.H, Hash_Blocks_256 (Message, Q),
            Pad_Block_256 (S), Padded_Block_256 (Message, Q));
         Lemma_Hash_Blocks_Unfold (Message, Q + 1);
         pragma Assert
           (Before_Length_256 (S) = Hash_Blocks_256 (Message, Q + 1));
         pragma Assert
           (Length_Block_256 (S, L) = Padded_Block_256 (Message, Q + 1));
         Lemma_Compress_Equal
           (Before_Length_256 (S), Hash_Blocks_256 (Message, Q + 1),
            Length_Block_256 (S, L), Padded_Block_256 (Message, Q + 1));
         Lemma_Hash_Blocks_Unfold (Message, Q + 2);
         pragma Assert
           (Compress_256 (Before_Length_256 (S), Length_Block_256 (S, L)) =
              Hash_Blocks_256 (Message, Q + 2));
      end if;
   end Lemma_Finish;
end SMB.Spec.SHA2.Lemmas;
