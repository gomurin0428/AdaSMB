with Interfaces;

package body SMB.AES is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_16;

   subtype U8 is Interfaces.Unsigned_8;
   subtype U16 is Interfaces.Unsigned_16;

   --  A block as eight bit planes: bit J of Planes (I) is bit I of byte J.
   --  The S-box works on all sixteen bytes at once in this form.
   type Planes is array (0 .. 7) of U16;
   --  A product of two plane polynomials before reduction.
   type Product is array (0 .. 14) of U16;

   subtype Round_Number is Natural range 0 .. 14;
   subtype Four_Bytes is SMB.Bytes (0 .. 3);

   --  Each helper has a contract, if only Post => True, so that GNATprove
   --  proves it once on its own and its callers see only the contract.
   --  Without one, GNATprove inlines a local subprogram into every call, and
   --  with the nested calls in Inverse the proof of Encrypt and Expand_Key
   --  grew to about 50 GB of memory without finishing.

   function To_Planes (State : Block) return Planes
     with Post => True
   is
      Result : Planes := (others => 0);
   begin
      for I in Planes'Range loop
         for J in Block'Range loop
            Result (I) := Result (I)
              or Interfaces.Shift_Left
                   (U16 (Interfaces.Shift_Right (State (J), I) and 1), J);
         end loop;
      end loop;
      return Result;
   end To_Planes;

   function From_Planes (Value : Planes) return Block
     with Post => True
   is
      Result : Block := (others => 0);
   begin
      for J in Block'Range loop
         for I in Planes'Range loop
            Result (J) := Result (J)
              or Interfaces.Shift_Left
                   (U8 (Interfaces.Shift_Right (Value (I), J) and 1), I);
         end loop;
      end loop;
      return Result;
   end From_Planes;

   --  Reduces modulo the AES polynomial x^8 + x^4 + x^3 + x + 1, from the
   --  top term down: x^K = x^(K - 8) * (x^4 + x^3 + x + 1).
   function Reduce (Value : Product) return Planes
     with Post => True
   is
      R : Product := Value;
   begin
      for K in reverse 8 .. 14 loop
         R (K - 4) := R (K - 4) xor R (K);
         R (K - 5) := R (K - 5) xor R (K);
         R (K - 7) := R (K - 7) xor R (K);
         R (K - 8) := R (K - 8) xor R (K);
      end loop;
      return Planes (R (0 .. 7));
   end Reduce;

   function Multiply (Left, Right : Planes) return Planes
     with Post => True
   is
      P : Product := (others => 0);
   begin
      for I in Planes'Range loop
         for J in Planes'Range loop
            P (I + J) := P (I + J) xor (Left (I) and Right (J));
         end loop;
      end loop;
      return Reduce (P);
   end Multiply;

   --  Squaring is linear in GF(2^8): coefficient I moves to term 2 * I.
   function Square (Value : Planes) return Planes
     with Post => True
   is
      P : Product := (others => 0);
   begin
      for I in Planes'Range loop
         P (2 * I) := Value (I);
      end loop;
      return Reduce (P);
   end Square;

   --  X ** 254, the multiplicative inverse in GF(2^8), with 0 for 0.
   function Inverse (X : Planes) return Planes
     with Post => True
   is
      X2 : constant Planes := Square (X);
      X3 : constant Planes := Multiply (X2, X);
      X12 : constant Planes := Square (Square (X3));
      X14 : constant Planes := Multiply (X12, X2);
      X15 : constant Planes := Multiply (X12, X3);
      X240 : constant Planes := Square (Square (Square (Square (X15))));
   begin
      return Multiply (X240, X14);
   end Inverse;

   --  The affine constant 16#63#: bits 0, 1, 5 and 6 of every byte.
   Affine_Constant : constant Planes :=
     (0 | 1 | 5 | 6 => 16#FFFF#, others => 0);

   function Sub_Bytes (State : Block) return Block
     with Post => True
   is
      B : constant Planes := Inverse (To_Planes (State));
      S : Planes;
   begin
      for I in Planes'Range loop
         --  (4 + I) rather than (I + 4): the mutant (I - 4) mod 8 would be
         --  the same index, while (4 - I) mod 8 is not.
         S (I) := B (I) xor B ((4 + I) mod 8) xor B ((I + 5) mod 8)
           xor B ((I + 6) mod 8) xor B ((I + 7) mod 8) xor Affine_Constant (I);
      end loop;
      return From_Planes (S);
   end Sub_Bytes;

   --  Byte K is row K mod 4 of column K / 4; row R moves R columns left.
   function Shift_Rows (State : Block) return Block
     with Post => True
   is
      Result : Block;
   begin
      for K in Block'Range loop
         Result (K) := State (K mod 4 + 4 * ((K / 4 + K mod 4) mod 4));
      end loop;
      return Result;
   end Shift_Rows;

   function Times_2 (Value : U8) return U8 is
     (Interfaces.Shift_Left (Value, 1)
      xor 16#1B# * Interfaces.Shift_Right (Value, 7));

   function Column_Sum (State : Block; Column : Natural) return U8 is
     (State (4 * Column) xor State (4 * Column + 1)
      xor State (4 * Column + 2) xor State (4 * Column + 3))
   with Pre => Column <= 3;

   --  2 * A (R) + 3 * A (R + 1) + A (R + 2) + A (R + 3)
   --  = A (R) + (sum of the column) + 2 * (A (R) + A (R + 1)).
   function Mix_Columns (State : Block) return Block
     with Post => True
   is
      Result : Block;
   begin
      for K in Block'Range loop
         Result (K) := State (K) xor Column_Sum (State, K / 4)
           xor Times_2 (State (K) xor State (K - K mod 4 + (K + 1) mod 4));
      end loop;
      return Result;
   end Mix_Columns;

   function Add_Round_Key
     (State : Block; Schedule : Key_Schedule; Round : Round_Number)
      return Block
     with Post => True
   is
      Result : Block;
   begin
      for K in Block'Range loop
         Result (K) := State (K) xor Schedule.Round_Keys (16 * Round + K);
      end loop;
      return Result;
   end Add_Round_Key;

   Round_Constants : constant SMB.Bytes (1 .. 10) :=
     (16#01#, 16#02#, 16#04#, 16#08#, 16#10#,
      16#20#, 16#40#, 16#80#, 16#1B#, 16#36#);

   --  SubWord: the first four bytes of SubBytes of a block that starts with
   --  the word.
   function Sub_Word (Value : Four_Bytes) return Four_Bytes
     with Post => True
   is
      Substituted : constant Block := Sub_Bytes
        ((Value (0), Value (1), Value (2), Value (3),
          --  adamutant:disable-next-line NumericLiteral: only the first four bytes are used
          others => 0));
   begin
      return Substituted (0 .. 3);
   end Sub_Word;

   --  FIPS 197 5.2, word by word: word I is word I - Nk xor a function of
   --  word I - 1, where Nk is the key's length in words, 4 or 8. Every
   --  Nk-th word takes SubWord (RotWord (word I - 1)) xor a round constant,
   --  and with AES-256 each word halfway between takes SubWord (word I - 1).
   --  The branches depend on the key's length, not on its bytes.
   procedure Expand_Key (Key : SMB.Bytes; Schedule : out Key_Schedule) is
      Long : constant Boolean := Key'Length = 32;
      Key_Words : constant Positive := (if Long then 8 else 4);
      Rounds : constant Round_Count := (if Long then 14 else 10);
      --  adamutant:disable-next-line NumericLiteral: the key and the loop below write every byte that Encrypt reads; the value is for flow analysis
      W : SMB.Bytes (0 .. 239) := (others => 0);
   begin
      W (0 .. Key'Length - 1) := Key;
      for I in Key_Words .. 4 * Rounds + 3 loop
         declare
            Previous : constant Four_Bytes := W (4 * I - 4 .. 4 * I - 1);
            Position : constant Natural := (if Long then I mod 8 else I mod 4);
            Temp : Four_Bytes := Previous;
         begin
            if Position = 0 then
               Temp := Sub_Word
                 ((Previous (1), Previous (2), Previous (3), Previous (0)));
               Temp (0) := Temp (0)
                 xor Round_Constants (if Long then I / 8 else I / 4);
            elsif Long and then Position = 4 then
               Temp := Sub_Word (Previous);
            end if;
            for K in Temp'Range loop
               W (4 * I + K) := W (4 * (I - Key_Words) + K) xor Temp (K);
            end loop;
         end;
      end loop;
      Schedule := (Round_Keys => W, Rounds => Rounds);
   end Expand_Key;

   function Encrypt (Schedule : Key_Schedule; Plain : Block) return Block is
      State : Block := Add_Round_Key (Plain, Schedule, 0);
   begin
      for Round in 1 .. Schedule.Rounds - 1 loop
         State := Add_Round_Key
           (Mix_Columns (Shift_Rows (Sub_Bytes (State))), Schedule, Round);
      end loop;
      return Add_Round_Key
        (Shift_Rows (Sub_Bytes (State)), Schedule, Schedule.Rounds);
   end Encrypt;

end SMB.AES;
