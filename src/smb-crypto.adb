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

   --  MD4 padding: the message, 16#80#, zeros, and the bit length in
   --  little-endian order.
   function Padded (Message : SMB.Bytes) return SMB.Bytes
     with Pre => Message'Length <= Maximum_Hash_Input,
       Post => Padded'Result'First = 0
         and then Padded'Result'Length = Padded_Length (Message'Length);

   function Padded (Message : SMB.Bytes) return SMB.Bytes is
      Length : constant Natural := Message'Length;
      Total  : constant Natural := Padded_Length (Length);
      Result : SMB.Bytes (0 .. Total - 1) := (others => 0);
      Bits   : constant U64 := U64 (Length) * 8;
   begin
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: copying an empty Message changes nothing
      if Length > 0 then
         Result (0 .. Length - 1) := Message;
      end if;
      Result (Length) := 16#80#;
      for I in 0 .. 7 loop
         Result (Total - 8 + I) :=
           SMB.Byte (Interfaces.Shift_Right (Bits, I * 8) and 16#FF#);
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
      Input : constant SMB.Bytes := Padded (Message);
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
      --  adamutant:disable-next-line NumericLiteral: every byte is stored before return; the value is for flow analysis
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

   SHA256_K : constant Round_Constants (0 .. 63) :=
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
   SHA256_IV : constant Hash_State :=
     (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
      16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);

   subtype Block_Bytes is SMB.Bytes (0 .. 63);

   procedure SHA256_Compress (H : in out Hash_State; Block : Block_Bytes)
     with Global => null
   is
      --  adamutant:disable-next-line NumericLiteral: the loops below write every word first; the value is for flow analysis
      W : Word_Array (0 .. 63) := (others => 0);
   begin
      for I in 0 .. 15 loop
         W (I) := Interfaces.Shift_Left (U32 (Block (I * 4)), 24)
           or Interfaces.Shift_Left (U32 (Block (I * 4 + 1)), 16)
           or Interfaces.Shift_Left (U32 (Block (I * 4 + 2)), 8)
           or U32 (Block (I * 4 + 3));
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
              --  adamutant:disable-next-line LogicalOperator: the two terms of Ch share no bit, so xor equals or
              + ((E and F) xor ((not E) and G)) + SHA256_K (I) + W (I);
            T2 := (Ror (A, 2) xor Ror (A, 13) xor Ror (A, 22))
              --  adamutant:disable-next-line LogicalOperator: or-ing in B and C still gives the majority
              + ((A and B) xor (A and C) xor (B and C));
            HH := G; G := F; F := E; E := D + T1;
            D := C; C := B; B := A; A := T1 + T2;
         end loop;
         H (0) := H (0) + A; H (1) := H (1) + B;
         H (2) := H (2) + C; H (3) := H (3) + D;
         H (4) := H (4) + E; H (5) := H (5) + F;
         H (6) := H (6) + G; H (7) := H (7) + HH;
      end;
   end SHA256_Compress;

   procedure SHA256_Start (Context : out SHA256_Context)
     with Post => Context.Total = 0
   is
   begin
      Context :=
        (H => SHA256_IV,
         --  adamutant:disable-next-line NumericLiteral: Update and Finish write every byte before it is read
         Block => (others => 0),
         Used => 0,
         Total => 0);
   end SHA256_Start;

   procedure SHA256_Update (Context : in out SHA256_Context; Message : SMB.Bytes)
     with Pre => Message'Length <= Maximum_Hash_Input
       and then Context.Total <= Maximum_Hash_Input - Message'Length,
       Post => Context.Total = Context.Total'Old + Message'Length
   is
   begin
      for I in Message'Range loop
         Context.Block (Context.Used) := Message (I);
         if Context.Used = Block_Position'Last then
            SHA256_Compress (Context.H, Context.Block);
            Context.Used := 0;
         else
            Context.Used := Context.Used + 1;
         end if;
         pragma Loop_Invariant (Context.Total = Context.Total'Loop_Entry);
      end loop;
      Context.Total := Context.Total + Message'Length;
   end SHA256_Update;

   procedure SHA256_Finish
     (Context : in out SHA256_Context; Digest : out Digest_256)
     with Pre => Context.Total <= Maximum_Hash_Input
   is
      Bits : constant U64 := U64 (Context.Total) * 8;
   begin
      Context.Block (Context.Used) := 16#80#;
      Context.Block (Context.Used + 1 .. 63) := (others => 0);
      if Context.Used >= 56 then
         SHA256_Compress (Context.H, Context.Block);
         Context.Block := (others => 0);
      end if;
      --  adamutant:disable-next-line NumericLiteral: byte 56, the top byte of the bit count, is 0 for every input up to Maximum_Hash_Input and is already cleared
      for I in 0 .. 7 loop
         Context.Block (56 + I) :=
           SMB.Byte (Interfaces.Shift_Right (Bits, (7 - I) * 8) and 16#FF#);
      end loop;
      SHA256_Compress (Context.H, Context.Block);
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: every byte is written below; the clear is for flow analysis
      Digest := (others => 0);
      for I in 0 .. 7 loop
         for J in 0 .. 3 loop
            Digest (I * 4 + J) := SMB.Byte
              (Interfaces.Shift_Right (Context.H (I), (3 - J) * 8) and 16#FF#);
         end loop;
      end loop;
   end SHA256_Finish;

   function SHA256 (Message : SMB.Bytes) return Digest_256 is
      Context : SHA256_Context;
      Digest : Digest_256;
   begin
      SHA256_Start (Context);
      SHA256_Update (Context, Message);
      SHA256_Finish (Context, Digest);
      return Digest;
   end SHA256;

   type Word64_Array is array (Natural range <>) of U64;
   subtype Shift_Count_64 is Natural range 1 .. 63;

   function Ror64 (Value : U64; Amount : Shift_Count_64) return U64 is
     (Interfaces.Shift_Right (Value, Amount)
      or Interfaces.Shift_Left (Value, 64 - Amount));

   SHA512_K : constant Word64_Array (0 .. 79) :=
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
   SHA512_IV : constant Hash_State_64 :=
     (16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#, 16#3C6EF372FE94F82B#,
      16#A54FF53A5F1D36F1#, 16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#,
      16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#);

   subtype Block_Bytes_128 is SMB.Bytes (0 .. 127);

   procedure SHA512_Compress (H : in out Hash_State_64; Block : Block_Bytes_128)
     with Global => null
   is
      W : Word64_Array (0 .. 79) := (others => 0);
   begin
      for I in 0 .. 15 loop
         for J in 0 .. 7 loop
            W (I) := Interfaces.Shift_Left (W (I), 8) or U64 (Block (I * 8 + J));
         end loop;
      end loop;
      for I in 16 .. 79 loop
         declare
            S0 : constant U64 := Ror64 (W (I - 15), 1)
              xor Ror64 (W (I - 15), 8)
              xor Interfaces.Shift_Right (W (I - 15), 7);
            S1 : constant U64 := Ror64 (W (I - 2), 19)
              xor Ror64 (W (I - 2), 61)
              xor Interfaces.Shift_Right (W (I - 2), 6);
         begin
            W (I) := W (I - 16) + S0 + W (I - 7) + S1;
         end;
      end loop;
      declare
         A : U64 := H (0); B : U64 := H (1);
         C : U64 := H (2); D : U64 := H (3);
         E : U64 := H (4); F : U64 := H (5);
         G : U64 := H (6); HH : U64 := H (7);
         T1, T2 : U64;
      begin
         for I in 0 .. 79 loop
            T1 := HH + (Ror64 (E, 14) xor Ror64 (E, 18) xor Ror64 (E, 41))
              + ((E and F) xor ((not E) and G)) + SHA512_K (I) + W (I);
            T2 := (Ror64 (A, 28) xor Ror64 (A, 34) xor Ror64 (A, 39))
              + ((A and B) xor (A and C) xor (B and C));
            HH := G; G := F; F := E; E := D + T1;
            D := C; C := B; B := A; A := T1 + T2;
         end loop;
         H (0) := H (0) + A; H (1) := H (1) + B;
         H (2) := H (2) + C; H (3) := H (3) + D;
         H (4) := H (4) + E; H (5) := H (5) + F;
         H (6) := H (6) + G; H (7) := H (7) + HH;
      end;
   end SHA512_Compress;

   procedure SHA512_Start (Context : out SHA512_Context) is
   begin
      Context :=
        (H => SHA512_IV, Block => (others => 0), Used => 0, Total => 0,
         Active => True);
   end SHA512_Start;

   procedure SHA512_Update
     (Context : in out SHA512_Context;
      Message : SMB.Bytes)
   is
   begin
      for I in Message'Range loop
         Context.Block (Context.Used) := Message (I);
         if Context.Used = Block_Position_128'Last then
            SHA512_Compress (Context.H, Context.Block);
            Context.Used := 0;
         else
            Context.Used := Context.Used + 1;
         end if;
         pragma Loop_Invariant (Context.Total = Context.Total'Loop_Entry);
         pragma Loop_Invariant (Context.Active);
      end loop;
      Context.Total := Context.Total + Message'Length;
   end SHA512_Update;

   procedure SHA512_Finish
     (Context : in out SHA512_Context;
      Digest : out Digest_512)
   is
      Bits : constant U64 := U64 (Context.Total) * 8;
   begin
      Context.Block (Context.Used) := 16#80#;
      Context.Block (Context.Used + 1 .. 127) := (others => 0);
      if Context.Used >= 112 then
         SHA512_Compress (Context.H, Context.Block);
         Context.Block := (others => 0);
      end if;
      --  The length field is the last 16 bytes. Its upper half stays zero
      --  for every input this package accepts.
      for I in 0 .. 7 loop
         Context.Block (120 + I) :=
           SMB.Byte (Interfaces.Shift_Right (Bits, (7 - I) * 8) and 16#FF#);
      end loop;
      SHA512_Compress (Context.H, Context.Block);
      Digest := (others => 0);
      for I in 0 .. 7 loop
         for J in 0 .. 7 loop
            Digest (I * 8 + J) := SMB.Byte
              (Interfaces.Shift_Right (Context.H (I), (7 - J) * 8) and 16#FF#);
         end loop;
      end loop;
      Context.Active := False;
   end SHA512_Finish;

   function SHA512 (Message : SMB.Bytes) return Digest_512 is
      Context : SHA512_Context;
      Digest : Digest_512;
   begin
      SHA512_Start (Context);
      SHA512_Update (Context, Message);
      SHA512_Finish (Context, Digest);
      return Digest;
   end SHA512;

   MD5_K : constant Round_Constants (0 .. 63) :=
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
   MD5_S : constant Round_Shifts (0 .. 63) :=
     (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21);
   MD5_IV : constant MD5_State :=
     (16#67452301#, 16#EFCDAB89#, 16#98BADCFE#, 16#10325476#);

   procedure MD5_Compress (H : in out MD5_State; Block : Block_Bytes)
     with Global => null
   is
      X : Block_Words;
      A : U32 := H (0); B : U32 := H (1);
      C : U32 := H (2); D : U32 := H (3);
      Fv, T : U32;
      Index : Natural;
   begin
      for I in X'Range loop
         X (I) := Get_Le (Block, I * 4);
      end loop;
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
         B := B + Rol (A + Fv + MD5_K (I) + X (Index), MD5_S (I));
         A := T;
      end loop;
      H (0) := H (0) + A; H (1) := H (1) + B;
      H (2) := H (2) + C; H (3) := H (3) + D;
   end MD5_Compress;

   procedure MD5_Start (Context : out MD5_Context)
     with Post => Context.Total = 0
   is
   begin
      Context :=
        (H => MD5_IV,
         --  adamutant:disable-next-line NumericLiteral: Update and Finish write every byte before it is read
         Block => (others => 0),
         Used => 0,
         Total => 0);
   end MD5_Start;

   procedure MD5_Update (Context : in out MD5_Context; Message : SMB.Bytes)
     with Pre => Message'Length <= Maximum_Hash_Input
       and then Context.Total <= Maximum_Hash_Input - Message'Length,
       Post => Context.Total = Context.Total'Old + Message'Length
   is
   begin
      for I in Message'Range loop
         Context.Block (Context.Used) := Message (I);
         if Context.Used = Block_Position'Last then
            MD5_Compress (Context.H, Context.Block);
            Context.Used := 0;
         else
            Context.Used := Context.Used + 1;
         end if;
         pragma Loop_Invariant (Context.Total = Context.Total'Loop_Entry);
      end loop;
      Context.Total := Context.Total + Message'Length;
   end MD5_Update;

   procedure MD5_Finish
     (Context : in out MD5_Context; Digest : out Digest_128)
     with Pre => Context.Total <= Maximum_Hash_Input
   is
      Bits : constant U64 := U64 (Context.Total) * 8;
   begin
      Context.Block (Context.Used) := 16#80#;
      Context.Block (Context.Used + 1 .. 63) := (others => 0);
      if Context.Used >= 56 then
         MD5_Compress (Context.H, Context.Block);
         Context.Block := (others => 0);
      end if;
      for I in 0 .. 7 loop
         Context.Block (56 + I) :=
           SMB.Byte (Interfaces.Shift_Right (Bits, I * 8) and 16#FF#);
      end loop;
      MD5_Compress (Context.H, Context.Block);
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: every byte is written below; the clear is for flow analysis
      Digest := (others => 0);
      Store_Le (Digest, 0, Context.H (0)); Store_Le (Digest, 4, Context.H (1));
      Store_Le (Digest, 8, Context.H (2)); Store_Le (Digest, 12, Context.H (3));
   end MD5_Finish;

   function MD5 (Message : SMB.Bytes) return Digest_128 is
      Context : MD5_Context;
      Digest : Digest_128;
   begin
      MD5_Start (Context);
      MD5_Update (Context, Message);
      MD5_Finish (Context, Digest);
      return Digest;
   end MD5;

   procedure HMAC_MD5_Start
     (Context : out HMAC_MD5_Context;
      Key : SMB.Bytes)
   is
      K0 : SMB.Bytes (0 .. 63) := (others => 0);
      --  adamutant:disable-next-line NumericLiteral: the loop below writes every byte; the value is for flow analysis
      Inner_Pad : SMB.Bytes (0 .. 63) := (others => 0);
   begin
      if Key'Length > 64 then
         K0 (0 .. 15) := MD5 (Key);
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: copying an empty Key changes nothing
      elsif Key'Length > 0 then
         K0 (0 .. Key'Length - 1) := Key;
      end if;
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: the loop below writes every byte; the clear is for flow analysis
      Context.Outer_Pad := (others => 0);
      for I in 0 .. 63 loop
         Inner_Pad (I) := K0 (I) xor 16#36#;
         Context.Outer_Pad (I) := K0 (I) xor 16#5C#;
      end loop;
      MD5_Start (Context.Inner);
      MD5_Update (Context.Inner, Inner_Pad);
      Context.Length := 0;
   end HMAC_MD5_Start;

   procedure HMAC_MD5_Update
     (Context : in out HMAC_MD5_Context;
      Message : SMB.Bytes)
   is
   begin
      MD5_Update (Context.Inner, Message);
      Context.Length := Context.Length + Message'Length;
   end HMAC_MD5_Update;

   procedure HMAC_MD5_Finish
     (Context : in out HMAC_MD5_Context;
      Digest : out Digest_128)
   is
      Inner_Digest : Digest_128;
      Outer : MD5_Context;
   begin
      MD5_Finish (Context.Inner, Inner_Digest);
      MD5_Start (Outer);
      MD5_Update (Outer, Context.Outer_Pad);
      MD5_Update (Outer, Inner_Digest);
      MD5_Finish (Outer, Digest);
      --  The wipe only clears secrets: nothing reads them afterwards.
      --  adamutant:disable NumericLiteral
      Context :=
        (Inner =>
           (H => (others => 0), Block => (others => 0), Used => 0, Total => 0),
         Outer_Pad => (others => 0),
         Length => 0);
      --  adamutant:enable NumericLiteral
   end HMAC_MD5_Finish;

   function HMAC_MD5 (Key, Message : SMB.Bytes) return Digest_128 is
      Context : HMAC_MD5_Context;
      Digest : Digest_128;
   begin
      HMAC_MD5_Start (Context, Key);
      HMAC_MD5_Update (Context, Message);
      HMAC_MD5_Finish (Context, Digest);
      return Digest;
   end HMAC_MD5;

   procedure HMAC_SHA256_Start
     (Context : out HMAC_SHA256_Context;
      Key : SMB.Bytes)
   is
      K0 : SMB.Bytes (0 .. 63) := (others => 0);
      --  adamutant:disable-next-line NumericLiteral: the loop below writes every byte; the value is for flow analysis
      Inner_Pad : SMB.Bytes (0 .. 63) := (others => 0);
   begin
      if Key'Length > 64 then
         K0 (0 .. 31) := SHA256 (Key);
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: copying an empty Key changes nothing
      elsif Key'Length > 0 then
         K0 (0 .. Key'Length - 1) := Key;
      end if;
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: the loop below writes every byte; the clear is for flow analysis
      Context.Outer_Pad := (others => 0);
      for I in 0 .. 63 loop
         Inner_Pad (I) := K0 (I) xor 16#36#;
         Context.Outer_Pad (I) := K0 (I) xor 16#5C#;
      end loop;
      SHA256_Start (Context.Inner);
      SHA256_Update (Context.Inner, Inner_Pad);
      Context.Length := 0;
   end HMAC_SHA256_Start;

   procedure HMAC_SHA256_Update
     (Context : in out HMAC_SHA256_Context;
      Message : SMB.Bytes)
   is
   begin
      SHA256_Update (Context.Inner, Message);
      Context.Length := Context.Length + Message'Length;
   end HMAC_SHA256_Update;

   procedure HMAC_SHA256_Finish
     (Context : in out HMAC_SHA256_Context;
      Digest : out Digest_256)
   is
      Inner_Digest : Digest_256;
      Outer : SHA256_Context;
   begin
      SHA256_Finish (Context.Inner, Inner_Digest);
      SHA256_Start (Outer);
      SHA256_Update (Outer, Context.Outer_Pad);
      SHA256_Update (Outer, Inner_Digest);
      SHA256_Finish (Outer, Digest);
      --  The wipe only clears secrets: nothing reads them afterwards.
      --  adamutant:disable NumericLiteral
      Context :=
        (Inner =>
           (H => (others => 0), Block => (others => 0), Used => 0, Total => 0),
         Outer_Pad => (others => 0),
         Length => 0);
      --  adamutant:enable NumericLiteral
   end HMAC_SHA256_Finish;

   function HMAC_SHA256 (Key, Message : SMB.Bytes) return Digest_256 is
      Context : HMAC_SHA256_Context;
      Digest : Digest_256;
   begin
      HMAC_SHA256_Start (Context, Key);
      HMAC_SHA256_Update (Context, Message);
      HMAC_SHA256_Finish (Context, Digest);
      return Digest;
   end HMAC_SHA256;

   function Constant_Time_Equal (Left, Right : SMB.Bytes) return Boolean is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Difference : SMB.Byte := 0;
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: for empty arrays the loop is empty too
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
