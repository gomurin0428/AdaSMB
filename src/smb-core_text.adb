package body SMB.Core_Text is
   pragma SPARK_Mode (On);

   function Byte_At (Value : String; Offset : Natural) return Natural
     with Pre => Offset < Value'Length,
       Post => Byte_At'Result <= 255;

   function Byte_At (Value : String; Offset : Natural) return Natural is
     (Character'Pos (Value (Value'First + Offset)));

   procedure Decode_UTF8
     (Value : String;
      Position : in out Natural;
      Scalar : out Natural;
      Status : out SMB.Core_Status)
     with Pre => Value'Length <= SMB.Maximum_Frame_Size
       and then Position <= Value'Length,
       Post => Position <= Value'Length
         and then (if Status = SMB.Ok then
           Position > Position'Old and then Scalar in 1 .. 16#10FFFF#
           and then Scalar not in 16#D800# .. 16#DFFF#);

   procedure Decode_UTF8
     (Value : String;
      Position : in out Natural;
      Scalar : out Natural;
      Status : out SMB.Core_Status) is
      B1 : Natural;
      B2, B3, B4 : Natural;
      Remaining : Natural;
   begin
      Scalar := 0;
      if Position >= Value'Length then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Remaining := Value'Length - Position;
      B1 := Byte_At (Value, Position);
      if B1 = 0 then
         Status := SMB.Invalid_Encoding;
      elsif B1 <= 16#7F# then
         Scalar := B1;
         Position := Position + 1;
         Status := SMB.Ok;
      elsif B1 in 16#C2# .. 16#DF# then
         if Remaining < 2 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         if B2 not in 16#80# .. 16#BF# then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#C0#) * 64 + B2 - 16#80#;
         Position := Position + 2;
         Status := SMB.Ok;
      elsif B1 in 16#E0# .. 16#EF# then
         if Remaining < 3 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         B3 := Byte_At (Value, Position + 2);
         if B2 not in 16#80# .. 16#BF#
           or else B3 not in 16#80# .. 16#BF#
           or else (B1 = 16#E0# and then B2 < 16#A0#)
           or else (B1 = 16#ED# and then B2 >= 16#A0#)
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#E0#) * 4_096
           + (B2 - 16#80#) * 64 + B3 - 16#80#;
         Position := Position + 3;
         Status := SMB.Ok;
      elsif B1 in 16#F0# .. 16#F4# then
         if Remaining < 4 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         B3 := Byte_At (Value, Position + 2);
         B4 := Byte_At (Value, Position + 3);
         if B2 not in 16#80# .. 16#BF#
           or else B3 not in 16#80# .. 16#BF#
           or else B4 not in 16#80# .. 16#BF#
           or else (B1 = 16#F0# and then B2 < 16#90#)
           or else (B1 = 16#F4# and then B2 > 16#8F#)
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#F0#) * 262_144
           + (B2 - 16#80#) * 4_096
           + (B3 - 16#80#) * 64 + B4 - 16#80#;
         Position := Position + 4;
         Status := SMB.Ok;
      else
         Status := SMB.Invalid_Encoding;
      end if;
   end Decode_UTF8;

   procedure UTF8_To_UTF16
     (Input : String;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Position : Natural := 0;
      procedure Store_Unit (Unit : Natural)
        with Pre => Output'Length <= 2 * SMB.Maximum_Frame_Size
          and then Unit <= 16#FFFF# and then Used <= Output'Length
          and then Output'Length - Used >= 2,
          Post => Used = Used'Old + 2;
      procedure Store_Unit (Unit : Natural) is
      begin
         Output (Output'First + Used) := SMB.Byte (Unit mod 256);
         Output (Output'First + Used + 1) := SMB.Byte (Unit / 256);
         Used := Used + 2;
      end Store_Unit;
      Scalar : Natural;
      Decode_Status : SMB.Core_Status;
   begin
      Used := 0;
      for Index in Output'Range loop
         Output (Index) := 0;
      end loop;
      if Output'Length < 2 * Input'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      while Position < Input'Length loop
         pragma Loop_Invariant (Position <= Input'Length);
         pragma Loop_Invariant (Used <= Output'Length);
         pragma Loop_Variant (Increases => Position);
         Decode_UTF8 (Input, Position, Scalar, Decode_Status);
         if Decode_Status /= SMB.Ok then
            Status := Decode_Status;
            return;
         end if;
         if Scalar <= 16#FFFF# then
            if Output'Length - Used < 2 then
               Status := SMB.Invalid_Length;
               return;
            end if;
            Store_Unit (Scalar);
         else
            if Output'Length - Used < 4 then
               Status := SMB.Invalid_Length;
               return;
            end if;
            Scalar := Scalar - 16#10000#;
            Store_Unit (16#D800# + Scalar / 1_024);
            Store_Unit (16#DC00# + Scalar mod 1_024);
         end if;
      end loop;
      Status := SMB.Ok;
   end UTF8_To_UTF16;

   procedure UTF16_To_UTF8
     (Input : SMB.Bytes;
      Output : out String;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Offset : Natural := 0;
      Scalar : Natural;
      First : Natural;
      Second : Natural;
      function Encoded_Size (Value : Natural) return Positive is
        (if Value <= 16#7F# then 1 elsif Value <= 16#7FF# then 2
         elsif Value <= 16#FFFF# then 3 else 4);
      procedure Emit_Byte (Value : Natural)
        with Pre => Value <= 255 and then Used < Output'Length,
          Post => Used = Used'Old + 1;
      procedure Emit_Byte (Value : Natural) is
      begin
         Output (Output'First + Used) := Character'Val (Value);
         Used := Used + 1;
      end Emit_Byte;
      procedure Emit_Scalar (Value : Natural)
        with Pre => Value <= 16#10FFFF# and then Used <= Output'Length
          and then Encoded_Size (Value) <= Output'Length - Used,
          Post => Used = Used'Old + Encoded_Size (Value);
      procedure Emit_Scalar (Value : Natural) is
      begin
         if Value <= 16#7F# then
            Emit_Byte (Value);
         elsif Value <= 16#7FF# then
            Emit_Byte (16#C0# + Value / 64);
            Emit_Byte (16#80# + Value mod 64);
         elsif Value <= 16#FFFF# then
            Emit_Byte (16#E0# + Value / 4_096);
            Emit_Byte (16#80# + (Value / 64) mod 64);
            Emit_Byte (16#80# + Value mod 64);
         else
            Emit_Byte (16#F0# + Value / 262_144);
            Emit_Byte (16#80# + (Value / 4_096) mod 64);
            Emit_Byte (16#80# + (Value / 64) mod 64);
            Emit_Byte (16#80# + Value mod 64);
         end if;
      end Emit_Scalar;
   begin
      Used := 0;
      for Index in Output'Range loop
         Output (Index) := Character'Val (0);
      end loop;
      if Input'Length mod 2 /= 0
        or else Output'Length < 2 * Input'Length
      then
         Status := SMB.Invalid_Length;
         return;
      end if;
      while Offset < Input'Length loop
         pragma Loop_Invariant (Offset <= Input'Length);
         pragma Loop_Invariant (Offset mod 2 = 0);
         pragma Loop_Invariant (Used <= Output'Length);
         pragma Loop_Variant (Increases => Offset);
         First := Natural (Input (Input'First + Offset))
           + Natural (Input (Input'First + Offset + 1)) * 256;
         Offset := Offset + 2;
         if First = 0 then
            Status := SMB.Invalid_Encoding;
            return;
         elsif First in 16#D800# .. 16#DBFF# then
            if Input'Length - Offset < 2 then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Second := Natural (Input (Input'First + Offset))
              + Natural (Input (Input'First + Offset + 1)) * 256;
            if Second not in 16#DC00# .. 16#DFFF# then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Scalar := 16#10000#
              + (First - 16#D800#) * 1_024 + Second - 16#DC00#;
            Offset := Offset + 2;
         elsif First in 16#DC00# .. 16#DFFF# then
            Status := SMB.Invalid_Encoding;
            return;
         else
            Scalar := First;
         end if;
         if Encoded_Size (Scalar) > Output'Length - Used then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Emit_Scalar (Scalar);
      end loop;
      Status := SMB.Ok;
   end UTF16_To_UTF8;

   procedure Validate_UTF16
     (Input : SMB.Bytes;
      Status : out SMB.Core_Status) is
      Offset : Natural := 0;
      First : Natural;
      Second : Natural;
   begin
      Status := SMB.Ok;
      if Input'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      while Offset < Input'Length loop
         pragma Loop_Invariant (Offset <= Input'Length);
         pragma Loop_Invariant (Offset mod 2 = 0);
         pragma Loop_Variant (Increases => Offset);
         First := Natural (Input (Input'First + Offset))
           + Natural (Input (Input'First + Offset + 1)) * 256;
         Offset := Offset + 2;
         if First = 0 then
            Status := SMB.Invalid_Encoding;
            return;
         elsif First in 16#D800# .. 16#DBFF# then
            if Input'Length - Offset < 2 then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Second := Natural (Input (Input'First + Offset))
              + Natural (Input (Input'First + Offset + 1)) * 256;
            if Second not in 16#DC00# .. 16#DFFF# then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Offset := Offset + 2;
         elsif First in 16#DC00# .. 16#DFFF# then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
      end loop;
   end Validate_UTF16;

   procedure Uppercase_NTLM_User
     (Input : String;
      Output : out String;
      Status : out SMB.Core_Status) is
      Character_Code : Natural;
   begin
      for Index in Output'Range loop
         Output (Index) := Character'Val (0);
      end loop;
      if Output'Length /= Input'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Input'Length > 0 then
         for Offset in 0 .. Input'Length - 1 loop
            Character_Code := Character'Pos (Input (Input'First + Offset));
            if Character_Code > 16#7F# then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if Character_Code in Character'Pos ('a') .. Character'Pos ('z') then
               Character_Code := Character_Code - 32;
            end if;
            Output (Output'First + Offset) := Character'Val (Character_Code);
         end loop;
      end if;
      Status := SMB.Ok;
   end Uppercase_NTLM_User;

   procedure Validate_Path
     (Input : String;
      Output : out String;
      Allow_Empty : Boolean;
      Status : out SMB.Core_Status) is
      Component_Start : Natural := 0;
   begin
      for I in Output'Range loop
         Output (I) := Character'Val (0);
      end loop;
      Status := SMB.Ok;
      if Input'Length = 0 then
         if not Allow_Empty then
            Status := SMB.Invalid_Value;
         end if;
         return;
      end if;
      for Offset in 0 .. Input'Length - 1 loop
         pragma Loop_Invariant (Component_Start <= Offset);
         declare
            C : constant Character := Input (Input'First + Offset);
            Component_Length : constant Natural := Offset - Component_Start;
         begin
            if C = Character'Val (0) or else C = ':' then
               Status := SMB.Invalid_Value;
               return;
            elsif C = '/' or else C = '\' then
               if Offset = 0
                 or else Offset = Input'Length - 1
                 or else Component_Length = 0
                 or else (Component_Length = 2
                          and then Input (Input'First + Component_Start
                                          .. Input'First + Offset - 1) = "..")
               then
                  Status := SMB.Invalid_Value;
                  return;
               end if;
               Output (Output'First + Offset) := '\';
               Component_Start := Offset + 1;
            else
               Output (Output'First + Offset) := C;
            end if;
         end;
      end loop;
      if Input'Length - Component_Start = 2
        and then Input (Input'First + Component_Start .. Input'Last) = ".."
      then
         Status := SMB.Invalid_Value;
      end if;
   end Validate_Path;

   procedure Validate_Share
     (Input : String;
      Status : out SMB.Core_Status) is
   begin
      Status := SMB.Ok;
      if Input'Length = 0 then
         Status := SMB.Invalid_Value;
         return;
      end if;
      for C of Input loop
         if C = Character'Val (0)
           or else C = ':'
           or else C = '/'
           or else C = '\'
         then
            Status := SMB.Invalid_Value;
            return;
         end if;
      end loop;
   end Validate_Share;
end SMB.Core_Text;
