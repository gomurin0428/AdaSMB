with Interfaces;

package body SMB.Crypto is
   pragma SPARK_Mode (On);
   subtype U32 is Interfaces.Unsigned_32;
   subtype U64 is Interfaces.Unsigned_64;
   use type SMB.Byte;
   use type U32;
   use type U64;

   type Word_Array is array (Natural range <>) of U32;
   type Block_Words is array (Natural range 0 .. 15) of U32;
   type Round_Constants is array (Natural range <>) of U32;
   subtype Shift_Count is Natural range 0 .. 31;
   type Round_Shifts is array (Natural range <>) of Shift_Count;

   function Rol (Value : U32; Amount : Shift_Count) return U32 is
     (Interfaces.Shift_Left (Value, Amount)
      or Interfaces.Shift_Right (Value, 32 - Amount));

   function Ror (Value : U32; Amount : Shift_Count) return U32 is
     (Interfaces.Shift_Right (Value, Amount)
      or Interfaces.Shift_Left (Value, 32 - Amount));

   function Padded_Length (Length : Natural) return Natural
     with Pre => Length <= Maximum_Hash_Input,
       Post => Padded_Length'Result >= Length + 9
         and then Padded_Length'Result <= Length + 72
         and then Padded_Length'Result mod 64 = 0;

   function Padded_Length (Length : Natural) return Natural is
   begin
      return ((Length + 72) / 64) * 64;
   end Padded_Length;

   function Padded (Message : SMB.Bytes; Little_Endian_Length : Boolean)
                   return SMB.Bytes
     with Pre => Message'Length <= Maximum_Hash_Input,
       Post => Padded'Result'First = 0
         and then Padded'Result'Length = Padded_Length (Message'Length);

   function Padded (Message : SMB.Bytes; Little_Endian_Length : Boolean)
                   return SMB.Bytes is
      Length : constant Natural := Message'Length;
      Total  : constant Natural := Padded_Length (Length);
      Result : SMB.Bytes (0 .. Total - 1) := (others => 0);
      Bits   : constant U64 := U64 (Length) * 8;
   begin
      if Length > 0 then
         Result (0 .. Length - 1) := Message;
      end if;
      Result (Length) := 16#80#;
      for I in 0 .. 7 loop
         declare
            Shift : constant Natural :=
              (if Little_Endian_Length then I * 8 else (7 - I) * 8);
         begin
            Result (Total - 8 + I) :=
              SMB.Byte (Interfaces.Shift_Right (Bits, Shift) and 16#FF#);
         end;
      end loop;
      return Result;
   end Padded;

   function Get_Le (Data : SMB.Bytes; Offset : Natural) return U32
     with Pre => Data'Length <= Maximum_Hash_Input + 72
       and then Offset <= Data'Length and then Data'Length - Offset >= 4;

   function Get_Le (Data : SMB.Bytes; Offset : Natural) return U32 is
   begin
      return U32 (Data (Data'First + Offset))
        or Interfaces.Shift_Left (U32 (Data (Data'First + Offset + 1)), 8)
        or Interfaces.Shift_Left (U32 (Data (Data'First + Offset + 2)), 16)
        or Interfaces.Shift_Left (U32 (Data (Data'First + Offset + 3)), 24);
   end Get_Le;

   procedure Store_Le (Data : in out SMB.Bytes; Offset : Natural; Value : U32)
     with Pre => Data'Length <= Maximum_Hash_Input + 72
       and then Offset <= Data'Length and then Data'Length - Offset >= 4;

   procedure Store_Le (Data : in out SMB.Bytes; Offset : Natural; Value : U32) is
   begin
      for I in 0 .. 3 loop
         Data (Data'First + Offset + I) :=
           SMB.Byte (Interfaces.Shift_Right (Value, I * 8) and 16#FF#);
      end loop;
   end Store_Le;

   function MD4 (Message : SMB.Bytes) return Digest_128 is
      Input : constant SMB.Bytes := Padded (Message, True);
      A, B, C, D : U32;
      AA, BB, CC, DD : U32;
      F1 : constant Round_Shifts (0 .. 15) :=
        (3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19);
      F2 : constant Round_Shifts (0 .. 15) :=
        (3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13);
      F3 : constant Round_Shifts (0 .. 15) :=
        (3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15);
      Orders_2 : constant Round_Shifts (0 .. 15) :=
        (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
      Orders_3 : constant Round_Shifts (0 .. 15) :=
        (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);
      State : Digest_128 := (others => 0);
   begin
      A := 16#67452301#;
      B := 16#EFCDAB89#;
      C := 16#98BADCFE#;
      D := 16#10325476#;
      for Block in 0 .. Input'Length / 64 - 1 loop
         declare
            X : Block_Words;
            function F (X1, X2, X3 : U32) return U32 is
              ((X1 and X2) or ((not X1) and X3));
            function G (X1, X2, X3 : U32) return U32 is
              ((X1 and X2) or (X1 and X3) or (X2 and X3));
            function H (X1, X2, X3 : U32) return U32 is (X1 xor X2 xor X3);
            T : U32;
            Index : Natural;
         begin
            for I in X'Range loop
               X (I) := Get_Le (Input, Block * 64 + I * 4);
            end loop;
            AA := A; BB := B; CC := C; DD := D;
            for I in 0 .. 15 loop
               T := Rol (A + F (B, C, D) + X (I), F1 (I));
               A := D; D := C; C := B; B := T;
            end loop;
            for I in 0 .. 15 loop
               Index := Orders_2 (I);
               T := Rol (A + G (B, C, D) + X (Index) + 16#5A827999#, F2 (I));
               A := D; D := C; C := B; B := T;
            end loop;
            for I in 0 .. 15 loop
               Index := Orders_3 (I);
               T := Rol (A + H (B, C, D) + X (Index) + 16#6ED9EBA1#, F3 (I));
               A := D; D := C; C := B; B := T;
            end loop;
            A := A + AA; B := B + BB; C := C + CC; D := D + DD;
         end;
      end loop;
      Store_Le (State, 0, A); Store_Le (State, 4, B);
      Store_Le (State, 8, C); Store_Le (State, 12, D);
      return State;
   end MD4;

   function MD5 (Message : SMB.Bytes) return Digest_128 is
      Input : constant SMB.Bytes := Padded (Message, True);
      K : constant Round_Constants (0 .. 63) :=
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
      S : constant Round_Shifts (0 .. 63) :=
        (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21);
      A, B, C, D : U32;
      AA, BB, CC, DD : U32;
      State : Digest_128 := (others => 0);
   begin
      A := 16#67452301#; B := 16#EFCDAB89#;
      C := 16#98BADCFE#; D := 16#10325476#;
      for Block in 0 .. Input'Length / 64 - 1 loop
         declare
            X : Block_Words;
            Fv, T : U32;
            Index : Natural;
         begin
            for I in X'Range loop
               X (I) := Get_Le (Input, Block * 64 + I * 4);
            end loop;
            AA := A; BB := B; CC := C; DD := D;
            for I in 0 .. 63 loop
               if I < 16 then
                  Fv := (B and C) or ((not B) and D); Index := I;
               elsif I < 32 then
                  Fv := (D and B) or ((not D) and C);
                  Index := (5 * I + 1) mod 16;
               elsif I < 48 then
                  Fv := B xor C xor D; Index := (3 * I + 5) mod 16;
               else
                  Fv := C xor (B or (not D)); Index := (7 * I) mod 16;
               end if;
               T := D;
               D := C; C := B;
               B := B + Rol (A + Fv + K (I) + X (Index), S (I));
               A := T;
            end loop;
            A := A + AA; B := B + BB; C := C + CC; D := D + DD;
         end;
      end loop;
      Store_Le (State, 0, A); Store_Le (State, 4, B);
      Store_Le (State, 8, C); Store_Le (State, 12, D);
      return State;
   end MD5;

   function SHA256 (Message : SMB.Bytes) return Digest_256 is
      Input : constant SMB.Bytes := Padded (Message, False);
      K : constant Round_Constants (0 .. 63) :=
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
      H : Word_Array (0 .. 7) :=
        (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
         16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);
      W : Word_Array (0 .. 63) := (others => 0);
      State : Digest_256 := (others => 0);
   begin
      for Block in 0 .. Input'Length / 64 - 1 loop
         for I in 0 .. 15 loop
            declare
               O : constant Natural := Block * 64 + I * 4;
            begin
               W (I) := Interfaces.Shift_Left (U32 (Input (O)), 24)
                 or Interfaces.Shift_Left (U32 (Input (O + 1)), 16)
                 or Interfaces.Shift_Left (U32 (Input (O + 2)), 8)
                 or U32 (Input (O + 3));
            end;
         end loop;
         for I in 16 .. 63 loop
            declare
               S0 : constant U32 := Ror (W (I - 15), 7)
                 xor Ror (W (I - 15), 18)
                 xor Interfaces.Shift_Right (W (I - 15), 3);
               S1 : constant U32 := Ror (W (I - 2), 17)
                 xor Ror (W (I - 2), 19)
                 xor Interfaces.Shift_Right (W (I - 2), 10);
            begin
               W (I) := W (I - 16) + S0 + W (I - 7) + S1;
            end;
         end loop;
         declare
            A : U32 := H (0); B : U32 := H (1);
            C : U32 := H (2); D : U32 := H (3);
            E : U32 := H (4); F : U32 := H (5);
            G : U32 := H (6); HH : U32 := H (7);
            T1, T2 : U32;
         begin
            for I in 0 .. 63 loop
               T1 := HH + (Ror (E, 6) xor Ror (E, 11) xor Ror (E, 25))
                 + ((E and F) xor ((not E) and G)) + K (I) + W (I);
               T2 := (Ror (A, 2) xor Ror (A, 13) xor Ror (A, 22))
                 + ((A and B) xor (A and C) xor (B and C));
               HH := G; G := F; F := E; E := D + T1;
               D := C; C := B; B := A; A := T1 + T2;
            end loop;
            H (0) := H (0) + A; H (1) := H (1) + B;
            H (2) := H (2) + C; H (3) := H (3) + D;
            H (4) := H (4) + E; H (5) := H (5) + F;
            H (6) := H (6) + G; H (7) := H (7) + HH;
         end;
      end loop;
      for I in 0 .. 7 loop
         for J in 0 .. 3 loop
            State (I * 4 + J) :=
              SMB.Byte (Interfaces.Shift_Right (H (I), (3 - J) * 8) and 16#FF#);
         end loop;
      end loop;
      return State;
   end SHA256;

   function HMAC_MD5 (Key, Message : SMB.Bytes) return Digest_128 is
      K0 : SMB.Bytes (0 .. 63) := (others => 0);
      Inner : SMB.Bytes (0 .. 63 + Message'Length) := (others => 0);
      Outer : SMB.Bytes (0 .. 79) := (others => 0);
   begin
      if Key'Length > 64 then
         declare
            D : constant SMB.Bytes := MD5 (Key);
         begin
            K0 (0 .. D'Length - 1) := D;
         end;
      elsif Key'Length > 0 then
         K0 (0 .. Key'Length - 1) := Key;
      end if;
      for I in 0 .. 63 loop
         Inner (I) := K0 (I) xor 16#36#;
         Outer (I) := K0 (I) xor 16#5C#;
      end loop;
      if Message'Length > 0 then
         Inner (64 .. Inner'Last) := Message;
      end if;
      declare
         ID : constant SMB.Bytes := MD5 (Inner);
      begin
         Outer (64 .. 79) := ID;
      end;
      return MD5 (Outer);
   end HMAC_MD5;

   function HMAC_SHA256 (Key, Message : SMB.Bytes) return Digest_256 is
      K0 : SMB.Bytes (0 .. 63) := (others => 0);
      Inner : SMB.Bytes (0 .. 63 + Message'Length) := (others => 0);
      Outer : SMB.Bytes (0 .. 95) := (others => 0);
   begin
      if Key'Length > 64 then
         declare
            D : constant SMB.Bytes := SHA256 (Key);
         begin
            K0 (0 .. D'Length - 1) := D;
         end;
      elsif Key'Length > 0 then
         K0 (0 .. Key'Length - 1) := Key;
      end if;
      for I in 0 .. 63 loop
         Inner (I) := K0 (I) xor 16#36#;
         Outer (I) := K0 (I) xor 16#5C#;
      end loop;
      if Message'Length > 0 then
         Inner (64 .. Inner'Last) := Message;
      end if;
      declare
         ID : constant SMB.Bytes := SHA256 (Inner);
      begin
         Outer (64 .. 95) := ID;
      end;
      return SHA256 (Outer);
   end HMAC_SHA256;

   function Constant_Time_Equal (Left, Right : SMB.Bytes) return Boolean is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Difference : SMB.Byte := 0;
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;
      if Left'Length > 0 then
         for I in 0 .. Left'Length - 1 loop
            Difference := Difference or
              (Left (Left'First + I) xor Right (Right'First + I));
            pragma Loop_Invariant
              ((Difference = 0) =
                 (for all J in 0 .. I =>
                    Left (Left'First + J) = Right (Right'First + J)));
         end loop;
      end if;
      return Difference = 0;
   end Constant_Time_Equal;
end SMB.Crypto;
